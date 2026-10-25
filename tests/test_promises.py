"""Promises of README.md, docs/THREAT-MODEL.md and PRIVACY.md that had no red test (Codex review
of the suite, 2026-09-27): the launchers fail closed without a usable Python, the transcript
scrub runs through the real paths, a refused wipe is reported, and no hook opens a network
connection.

Every value is generated here. Every subprocess gets a temp MAISECRETS_HOME with the plaintext
test store and tripwires for security, powershell and pbcopy first on PATH (Sandbox of
test_cli_matrix.py); HOME is never changed and ~/.maisecrets is never read.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402  first: a temp vault home, never the real one
Path(os.environ["MAISECRETS_HOME"]).mkdir(parents=True, exist_ok=True)
Path(os.environ["MAISECRETS_HOME"], "config.json").write_text('{"backend": "jsonfile", "allow_plaintext_store": true}')

from test_cli_matrix import JSONFILE, Sandbox, fake_value  # noqa: E402
import _hygiene  # noqa: E402

BASH = shutil.which("bash")
RUN_SH = ROOT / "hooks" / "run.sh"
RUN_CMD = ROOT / "hooks" / "run.cmd"
EVENTS = ("user-prompt", "pre-tool", "post-tool-failure", "post-tool", "session-start")
# the absolute places run.sh tries after the PATH; the test points them into the sandbox, so a
# Python installed on this machine cannot answer for the missing one
ABSOLUTE_PYTHONS = ("/opt/homebrew/bin/python3", "/usr/local/bin/python3",
                    "/Library/Frameworks/Python.framework/Versions/Current/bin/python3")

# a python3 that says it is 3.8: the probe of run.sh gets 60 + minor, as from a real 3.8, and any other call
# (a run of dispatch.py) is recorded in the tripwire
_PY38 = """#!/bin/sh
case "$2" in
  *"sys.exit(0 if v >= (3, 9) else 60 + v[1]"*) exit 68 ;;
esac
echo "python3 $*" >> "$MS_TEST_TRIPWIRE"
exit 0
"""


def assert_refuses(case: unittest.TestCase, event: str, r: subprocess.CompletedProcess) -> None:
    """A hook that cannot work refuses in the form both clients read: JSON on stdout and exit 0.
    Exit 2 blocks in Claude Code only; Codex runs the tool when a hook exits 2 (harness/codex.py)."""
    case.assertEqual(r.returncode, 0, r.stderr)
    out = json.loads(r.stdout)
    if event == "user-prompt":
        case.assertEqual(out["decision"], "block")
    elif event == "pre-tool":
        case.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny")
        case.assertEqual(out["hookSpecificOutput"]["hookEventName"], "PreToolUse")
    elif event == "post-tool":
        # Claude Code's shape for a Claude payload; Codex's strict schema drops an answer that carries
        # Claude's updatedToolOutput, so a Codex payload (turn_id) gets decision/reason only
        case.assertEqual(set(out), {"hookSpecificOutput"}, out)
        case.assertIn("withheld", out["hookSpecificOutput"]["updatedToolOutput"])
    else:
        case.assertIn("systemMessage", out)


@unittest.skipIf(BASH is None, "no bash")
class LauncherFailsClosedTests(unittest.TestCase):
    """README: maisecrets needs Python 3.9+. Without it every hook must refuse, never pass."""

    def setUp(self):
        self.sb = Sandbox(JSONFILE, backend="jsonfile")
        self.addCleanup(self.sb.remove)
        text = RUN_SH.read_text(encoding="utf-8")
        for p in ABSOLUTE_PYTHONS:
            self.assertIn(p, text, "run.sh changed its candidates; update ABSOLUTE_PYTHONS")
            text = text.replace(p, str(self.sb.root / "abs" / p.lstrip("/")))
        # the copy sits next to the real dispatch.py name, so a launcher that runs it is seen
        self.hooks = self.sb.root / "hooks"
        self.hooks.mkdir()
        (self.hooks / "run.sh").write_text(text, encoding="utf-8")
        (self.hooks / "dispatch.py").write_text("raise SystemExit('dispatch.py ran')\n", encoding="utf-8")
        # only the tools run.sh needs besides a Python; no python3, python or py on this PATH
        self.tools = self.sb.root / "tools"
        self.tools.mkdir()
        # mkdir: the incident marker after the answer (docs/DIAGNOSTICS.md, section 3)
        for tool in ("dirname", "mkdir"):
            os.symlink(shutil.which(tool), self.tools / tool)

    def launch(self, event: str) -> subprocess.CompletedProcess:
        env = self.sb.env()
        env["PATH"] = os.pathsep.join((str(self.sb.bin), str(self.tools)))
        r = subprocess.run([BASH, str(self.hooks / "run.sh"), event], input='{"prompt": "x"}',
                           capture_output=True, text=True, env=env, timeout=30)
        trip = self.sb.root / "tripwire"
        self.assertFalse(trip.exists(), trip.read_text() if trip.exists() else "")
        return r

    def check_all_events(self, found: str) -> None:
        for event in EVENTS:
            with self.subTest(event):
                r = self.launch(event)
                self.assertNotIn("dispatch.py ran", r.stderr)
                said = r.stdout + r.stderr
                if found == "none" and sys.platform == "win32" and " gave no answer in " in said:
                    # Git Bash on a loaded windows-latest runner: twelve launches of a missing command passed the
                    # 2 s budget, so the launcher named the candidate it was at (2026-10-19). The answer is the
                    # same refusal; only the reason names a candidate instead of none
                    self.assertRegex(said, r"needs Python 3\.9 or newer on the PATH of the client "
                                           r"\(found: [\w. -]+ gave no answer in \d+ s\)")
                else:
                    self.assertIn(f"maisecrets needs Python 3.9 or newer on the PATH of the client (found: {found})",
                                  said)
                if event == "post-tool":
                    # Claude Code ignores exit 2 after a tool: the JSON itself must withhold
                    self.assertEqual(r.returncode, 0)
                    out = json.loads(r.stdout)
                    self.assertIn("Tool output withheld", out["hookSpecificOutput"]["updatedToolOutput"])
                    self.assertEqual(out["hookSpecificOutput"]["hookEventName"], "PostToolUse")
                elif event == "session-start":
                    self.assertEqual(r.returncode, 0)
                    self.assertTrue(json.loads(r.stdout)["systemMessage"].endswith(
                        "every prompt and every tool call is blocked."))
                else:
                    assert_refuses(self, event, r)
                    self.assertIn("Until then every prompt and every tool call is blocked.", r.stdout)

    def test_no_python_on_the_path_blocks_every_event(self):
        self.check_all_events("none")

    def test_no_python_leaves_one_marker_for_the_incident_report(self):
        # docs/DIAGNOSTICS.md, section 3: the launcher cannot write the record, so it leaves a marker after its answer
        self.launch("user-prompt")
        self.launch("pre-tool")
        self.assertEqual(sorted(p.name for p in self.sb.home.glob("incident-marker.*")),
                         ["incident-marker.launcher.no-python"], "one marker; a second failure coalesces")
        self.assertTrue((self.sb.home / "incident-marker.launcher.no-python").is_dir())

    def test_no_marker_into_a_symlinked_home(self):
        if os.name == "nt":
            self.skipTest("symlinks need privileges on Windows")
        target = Path(tempfile.mkdtemp(prefix="maisecrets-target-"))
        self.addCleanup(shutil.rmtree, target, True)
        link = self.sb.root / "linked-home"
        link.symlink_to(target)
        env = self.sb.env()
        env["PATH"] = os.pathsep.join((str(self.sb.bin), str(self.tools)))
        env["MAISECRETS_HOME"] = str(link)
        subprocess.run([BASH, str(self.hooks / "run.sh"), "user-prompt"], input='{"prompt": "x"}',
                       capture_output=True, text=True, env=env, timeout=30)
        self.assertEqual(os.listdir(target), [])

    def test_a_python_older_than_3_11_blocks_every_event_and_is_named(self):
        fake = self.tools / "python3"
        fake.write_text(_PY38, encoding="utf-8")
        fake.chmod(0o700)
        self.check_all_events("python3 is 3.8")


# python3 candidates in front of a working Python. Each one fails or stalls its probe in another way; a probe must
# hold no descriptor of the hook, and all probes together get 2 s (hooks/run.sh, BUDGET)
_STALLING_PYTHONS = {
    # a wrapper that never answers
    "hangs": "#!/bin/sh\nexec sleep 30\n",
    # a wrapper that fails and leaves a job in the background on the descriptors it got (a shim, a version manager)
    "leaves_a_job_on_its_stdout": "#!/bin/sh\n( sleep 30 ) &\nexit 1\n",
    "leaves_a_job_on_its_stderr": "#!/bin/sh\n( sleep 30 >/dev/null ) &\nexit 1\n",
    # a wrapper that reads its stdin: the payload is the hook's stdin
    "reads_stdin": "#!/bin/sh\ncat >/dev/null\nexit 1\n",
    # a wrapper that prints a wrong version and fails
    "prints_a_wrong_version": "#!/bin/sh\necho 3.12\nexit 1\n",
}
# the stand-in for dispatch.py: it shows that the launcher started it and that the payload reached it whole
_DISPATCH_ECHO = ("import json, sys\nprint(json.dumps({'decision': 'block', 'reason': 'dispatch ran', "
                  "'payload': sys.stdin.read()}))\n")


@unittest.skipIf(BASH is None or os.name == "nt", "the probes of run.sh, POSIX (Git Bash has no fake shell scripts)")
class LauncherProbeHoldsNothingTests(unittest.TestCase):
    """A python candidate whose probe hangs or leaves a job on the hook's stdout kept run.sh waiting (30 s and more,
    measured): past the client's timeout, and both clients let the call through then (Claude Code 2.1.302 and
    codex-cli 0.162.0, measured 2026-10-17). Codex also waits until the hook's stdout closes. The launcher must
    finish within its bound, with the verdict of the working Python or a refusal, and hold no descriptor open."""
    LIMIT = 5.0   # the budget of 2 s plus a loaded machine; a held descriptor holds the hook for 30 s

    def setUp(self):
        self.sb = Sandbox(JSONFILE, backend="jsonfile")
        self.addCleanup(self.sb.remove)
        text = RUN_SH.read_text(encoding="utf-8")
        for p in ABSOLUTE_PYTHONS:
            text = text.replace(p, str(self.sb.root / "abs" / p.lstrip("/")))
        self.hooks = self.sb.root / "hooks"
        self.hooks.mkdir()
        (self.hooks / "run.sh").write_text(text, encoding="utf-8")
        (self.hooks / "dispatch.py").write_text(_DISPATCH_ECHO, encoding="utf-8")
        self.fake = self.sb.root / "fake"
        self.fake.mkdir()
        # the working Python is the second candidate, `python`; sleep is on the PATH as on every client
        self.tools = self.sb.root / "tools"
        self.tools.mkdir()
        os.symlink(sys.executable, self.tools / "python")
        for tool in ("dirname", "mkdir", "cat", "sleep"):
            os.symlink(shutil.which(tool), self.tools / tool)

    def launch(self, body: str | None, event: str = "pre-tool",
               ignored: tuple = ()) -> tuple[subprocess.CompletedProcess, float]:
        for old in self.fake.iterdir():
            old.unlink()
        if body is not None:
            (self.fake / "python3").write_text(body, encoding="utf-8")
            (self.fake / "python3").chmod(0o700)
        env = self.sb.env()
        env["PATH"] = os.pathsep.join((str(self.fake), str(self.sb.bin), str(self.tools)))
        payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": "echo probe-payload"}})
        t0 = time.monotonic()
        # capture_output reads until both pipes close, as Codex does: a descriptor that a probe's job holds shows here
        p = subprocess.Popen([BASH, str(self.hooks / "run.sh"), event], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, text=True, env=env, start_new_session=True,
                             # a client can start its hooks with a signal ignored; the shell cannot trap that one
                             preexec_fn=(lambda: [signal.signal(s, signal.SIG_IGN) for s in ignored])
                             if ignored else None)
        try:
            out, err = p.communicate(payload, timeout=60)
        finally:
            # the jobs the fakes left: only the group this test started
            try:
                os.killpg(p.pid, 9)
            except (ProcessLookupError, PermissionError):
                pass
        return subprocess.CompletedProcess(p.args, p.returncode, out, err), time.monotonic() - t0

    def test_a_probe_that_fails_or_holds_a_descriptor_does_not_hold_the_hook(self):
        for case in ("leaves_a_job_on_its_stdout", "leaves_a_job_on_its_stderr", "reads_stdin",
                     "prints_a_wrong_version"):
            with self.subTest(case):
                r, took = self.launch(_STALLING_PYTHONS[case])
                self.assertLess(took, self.LIMIT, f"run.sh took {took:.1f} s: a probe held the hook")
                self.assertEqual(r.returncode, 0, r.stderr)
                out = json.loads(r.stdout)
                self.assertEqual(out["reason"], "dispatch ran", "the working Python must answer")
                self.assertIn("probe-payload", out["payload"], "the payload must reach dispatch.py whole")
                self.assertEqual(r.stderr, "")

    def test_a_probe_that_never_answers_is_stopped_and_the_hook_refuses(self):
        for event in EVENTS:
            with self.subTest(event):
                r, took = self.launch(_STALLING_PYTHONS["hangs"], event)
                self.assertLess(took, self.LIMIT, f"run.sh took {took:.1f} s past its budget")
                self.assertGreaterEqual(took, 1.5, "the budget is 2 s: a refusal before it is a false block")
                self.assertIn("(found: python3 gave no answer in 2 s)", r.stdout)
                self.assertNotIn("dispatch ran", r.stdout)
                self.assertEqual(r.stderr, "", "the end of the stopped probe is not reported")
                assert_refuses(self, event, r)

    def test_a_signal_ignored_by_the_client_does_not_take_the_bound(self):
        # USR1 ignored when the launcher starts: the timer must use another signal (codex review, 2026-10-17)
        r, took = self.launch(_STALLING_PYTHONS["hangs"], "user-prompt", ignored=(signal.SIGUSR1,))
        self.assertLess(took, self.LIMIT, f"the launcher took {took:.1f} s: the timer's signal was ignored")
        self.assertIn("(found: python3 gave no answer in 2 s)", r.stdout)
        assert_refuses(self, "user-prompt", r)

    def test_a_good_python3_first_answers_alone(self):
        # the normal machine: python3 is the first candidate and works; `python` is taken away, so only python3
        # can answer
        (self.tools / "python").unlink()
        self.addCleanup(lambda: os.symlink(sys.executable, self.tools / "python"))
        r, took = self.launch(f"#!/bin/sh\nexec {sys.executable} \"$@\"\n")
        out = json.loads(r.stdout)
        self.assertEqual(out["reason"], "dispatch ran")
        self.assertIn("probe-payload", out["payload"])
        self.assertLess(took, self.LIMIT)

    def test_without_a_stalling_candidate_the_first_python_answers(self):
        r, took = self.launch(None)
        self.assertEqual(json.loads(r.stdout)["reason"], "dispatch ran")
        self.assertLess(took, self.LIMIT)


_NO_POSIX_SH = shutil.which("sh") is None or os.name == "nt"
_POSIX_ONLY = "the POSIX hook command runs through sh; the Windows command is commandWindows"


@unittest.skipIf(_NO_POSIX_SH, _POSIX_ONLY)
class MovedPluginFolderFailsClosedTests(unittest.TestCase):
    """A plugin update moves the folder of an open session (anthropics/claude-code#97847). The client
    still runs the command of hooks/hooks.json with the old ${CLAUDE_PLUGIN_ROOT}; `bash <missing
    file>` exits 127, which the client reads as no objection, so every hook failed open and an
    address went to the model (field report on 0.5.8, 2026-09-28). Each command runs here exactly as
    the client runs it, through a shell, with a root that does not exist."""
    HINT = "/reload-plugins"

    def assert_refused(self, event: str, r: subprocess.CompletedProcess) -> None:
        assert_refuses(self, event, r)

    def commands(self) -> list:
        """(event, command) of every hook group: an event with two groups (PreToolUse: the main matcher and
        apply_patch, 0.6.40) has both, so one cannot hide the other."""
        data = json.loads((ROOT / "hooks" / "hooks.json").read_text(encoding="utf-8"))
        out = []
        for groups in data["hooks"].values():
            for group in groups:
                for hook in group["hooks"]:
                    event = next(e for e in EVENTS if f" {e};" in hook["command"] or hook["command"].endswith(f" {e}"))
                    out.append((event, hook["command"]))
        self.assertEqual(sorted({e for e, _c in out}), sorted(EVENTS), "every event has a command")
        return out

    def run_command(self, command: str, root: Path) -> subprocess.CompletedProcess:
        env = {k: v for k, v in os.environ.items() if not k.startswith("CLAUDE")}
        env["CLAUDE_PLUGIN_ROOT"] = str(root)
        return subprocess.run(["sh", "-c", command], input='{"prompt": "x"}', capture_output=True, text=True,
                              env=env, timeout=30)

    def test_a_missing_plugin_folder_blocks_every_event(self):
        gone = Path(tempfile.mkdtemp(prefix="maisecrets-moved-")) / "maisecrets"
        for event, command in self.commands():
            with self.subTest(event):
                r = self.run_command(command, gone)
                self.assertIn(self.HINT, r.stdout + r.stderr)
                if event == "post-tool":
                    # exit 2 is ignored after a tool ran: the JSON itself must withhold the output
                    self.assert_refused(event, r)
                elif event in ("session-start", "post-tool-failure"):
                    self.assertEqual(r.returncode, 0)
                    self.assertIn("folder is gone", json.loads(r.stdout)["systemMessage"])
                else:
                    self.assert_refused(event, r)

    def test_a_present_plugin_folder_runs_the_launcher(self):
        # the fallback must not replace the launcher: with the real root, the launcher answers
        for event, command in self.commands():
            if event != "user-prompt":
                continue
            r = self.run_command(command, ROOT)
            self.assertNotIn("folder is gone", r.stdout + r.stderr)
            self.assertEqual(r.returncode, 0, r.stderr)


class PowerShellPartFailsClosedTests(MovedPluginFolderFailsClosedTests):
    """The PowerShell half of each hooks.json command (Claude Code on Windows without Git Bash runs it,
    2.1.284), run here the way that client starts it: `${CLAUDE_PLUGIN_ROOT}` rewritten to
    `${env:CLAUDE_PLUGIN_ROOT}`, `pwsh -NoProfile -NonInteractive -Command`. pwsh runs on the GitHub
    Windows and macOS runners; the Windows e2e project runs it with the real client in pwsh 7 and 5.1."""

    __unittest_skip__ = False                     # the POSIX parent is skipped on Windows; pwsh runs there too
    __unittest_skip_why__ = ""

    def setUp(self):
        self.pwsh = shutil.which("pwsh")
        if not self.pwsh:
            self.skipTest("pwsh is not installed")

    def run_command(self, command: str, root: Path) -> subprocess.CompletedProcess:
        for n in ("CLAUDE_PROJECT_DIR", "CLAUDE_PLUGIN_ROOT", "CLAUDE_PLUGIN_DATA"):
            command = command.replace("${" + n + "}", "${env:" + n + "}")
        env = {k: v for k, v in os.environ.items() if not k.startswith("CLAUDE")}
        env["CLAUDE_PLUGIN_ROOT"] = str(root)
        return subprocess.run([self.pwsh, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command",
                               command], input='{"prompt": "x"}', capture_output=True, text=True, env=env,
                              timeout=60)

    def test_a_present_plugin_folder_runs_the_launcher(self):
        pass                                     # the launcher is a .cmd file: the Windows e2e runs it

    def test_a_launcher_that_does_not_start_blocks_every_event(self):
        # run.cmd is a directory here: PowerShell cannot start it on any system, as when cmd.exe is blocked
        root = Path(tempfile.mkdtemp(prefix="maisecrets-nostart-")) / "maisecrets"
        (root / "hooks" / "run.cmd").mkdir(parents=True)
        self.addCleanup(shutil.rmtree, root.parent, True)
        for event, command in self.commands():
            with self.subTest(event):
                r = self.run_command(command, root)
                self.assertIn("could not start hooks/run.cmd", r.stdout)
                if event == "session-start":
                    self.assertEqual(r.returncode, 0)
                else:
                    assert_refuses(self, event, r)


class CmdExeFailsClosedTests(MovedPluginFolderFailsClosedTests):
    """The commandWindows of each hook, which Codex on Windows runs as `cmd.exe /C "<command>"` with the plugin
    root written in. Codex removes the folder of the old version when it installs a new one (codex-cli
    0.159.0, measured 2026-09-29), and a command that cannot start lets Codex run the tool unguarded."""
    __unittest_skip__ = False   # the POSIX parent is skipped on Windows; this class is the Windows one
    __unittest_skip_why__ = ""
    HINT = "codex resume"

    def assert_refused(self, event: str, r: subprocess.CompletedProcess) -> None:
        if event != "post-tool":
            return assert_refuses(self, event, r)
        # Codex reads a block decision after a tool ran as the withheld result; its schema drops Claude's form
        self.assertEqual(r.returncode, 0, r.stderr)
        out = json.loads(r.stdout)
        self.assertEqual(out.get("decision"), "block", out)
        self.assertIn("withheld", out["reason"])

    def setUp(self):
        if os.name != "nt":
            self.skipTest("cmd.exe runs on Windows only; the GitHub Windows runner and the e2e project run it")

    def commands(self) -> list:
        data = json.loads((ROOT / "hooks" / "hooks.json").read_text(encoding="utf-8"))
        found = [hook["commandWindows"] for groups in data["hooks"].values() for group in groups
                 for hook in group["hooks"]]
        out = [(next(e for e in EVENTS if f" {e})" in c), c) for c in found]
        self.assertEqual(sorted({e for e, _c in out}), sorted(EVENTS), "every event has a Windows command")
        return out

    def run_command(self, command: str, root: Path) -> subprocess.CompletedProcess:
        env = {k: v for k, v in os.environ.items() if not k.startswith("CLAUDE")}
        # Codex writes the root into the text; both slash styles, since the command itself uses /
        line = command.replace("${CLAUDE_PLUGIN_ROOT}", str(root).replace("\\", self.SLASH))
        return subprocess.run(f'cmd.exe /C "{line}"', input='{"prompt": "x"}', capture_output=True, text=True,
                              env=env, timeout=60)

    SLASH = "\\"

    def stub_root(self, parent: str) -> Path:
        """A plugin folder whose launcher exits 7: its exit code must come through the if/else of the command."""
        root = Path(tempfile.mkdtemp(prefix="maisecrets-stub-")) / parent / "maisecrets"
        (root / "hooks").mkdir(parents=True)
        (root / "hooks" / "dispatch.py").write_text("", encoding="utf-8")
        (root / "hooks" / "run.cmd").write_text("@exit /b 7\r\n", encoding="utf-8")
        self.addCleanup(shutil.rmtree, root.parents[1], True)
        return root

    def test_the_exit_code_of_the_launcher_comes_through(self):
        for parent in ("plain", "Program Files (x86)"):
            root = self.stub_root(parent)
            for event, command in self.commands():
                with self.subTest(parent=parent, event=event):
                    self.assertEqual(self.run_command(command, root).returncode, 7)

    def test_a_missing_folder_under_a_path_with_spaces_and_parentheses_blocks(self):
        gone = Path(tempfile.mkdtemp(prefix="maisecrets-moved-")) / "Program Files (x86)" / "maisecrets"
        for event, command in self.commands():
            with self.subTest(event):
                r = self.run_command(command, gone)
                if event == "session-start":
                    self.assertIn("folder is gone", json.loads(r.stdout)["systemMessage"])
                else:
                    self.assert_refused(event, r)

    def test_a_folder_that_lost_its_dispatcher_blocks(self):
        # Codex deletes the old version folder while the session runs: run.cmd may still be there
        root = self.stub_root("half-deleted")
        (root / "hooks" / "dispatch.py").unlink()
        for event, command in self.commands():
            with self.subTest(event):
                r = self.run_command(command, root)
                if event == "session-start":
                    self.assertIn("folder is gone", json.loads(r.stdout)["systemMessage"])
                else:
                    self.assert_refused(event, r)


class RunCmdFindsAnInstallOffThePathTests(unittest.TestCase):
    """The python.org installer (also through winget) leaves PATH alone unless asked: run.cmd looks in its install
    folder (reported 2026-09-30: Python 3.12.10 installed, maisecrets said it needs Python)."""

    def setUp(self):
        if os.name != "nt":
            self.skipTest("cmd.exe runs on Windows only; the GitHub Windows runner and the e2e project run it")

    def test_a_python_only_in_the_install_folder_runs_the_hook(self):
        local = Path(tempfile.mkdtemp(prefix="maisecrets-localappdata-"))
        self.addCleanup(shutil.rmtree, local, True)
        (local / "Programs" / "Python").mkdir(parents=True)
        # a junction to this Python, where the per-user installer puts it; no admin right needed for one
        target = local / "Programs" / "Python" / "Python312"
        subprocess.run(f'mklink /J "{target}" "{sys.base_prefix}"', shell=True, check=True,
                       capture_output=True)
        self.addCleanup(lambda: os.rmdir(target))
        env = {k: v for k, v in os.environ.items() if not k.startswith("CLAUDE")}
        # a PATH with no Python and no py launcher; the real install folder of this Python, not a venv
        env["PATH"] = os.path.join(os.environ["SystemRoot"], "System32")
        env["LOCALAPPDATA"] = str(local)
        if os.path.exists(os.path.join(os.environ["SystemRoot"], "py.exe")):
            # the all-users py launcher would answer first; a wrong SystemRoot can hurt Python, so only then
            env["SystemRoot"] = str(local)
        env["ProgramFiles"] = str(local / "none")
        home = Path(tempfile.mkdtemp(prefix="maisecrets-home-"))
        self.addCleanup(shutil.rmtree, home, True)
        (home / "config.json").write_text(json.dumps({"backend": "jsonfile", "allow_plaintext_store": True}))
        env["MAISECRETS_HOME"] = str(home)
        r = subprocess.run([os.path.join(os.environ["SystemRoot"], "System32", "cmd.exe"), "/C",
                            str(RUN_CMD), "user-prompt"], input='{"prompt": "x", "session_id": "S", "prompt_id": "p"}',
                           capture_output=True, text=True, env=env, timeout=60)
        self.assertNotIn("needs Python", r.stdout + r.stderr)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        # the start record says which event ran with which environment, and nothing of the payload
        # not in the plugin folder: Codex binds the approval of the hooks to its contents (openai/codex#54619)
        self.assertFalse((RUN_CMD.parent / "last-start.txt").exists(), "run.cmd wrote into the plugin folder")
        record = (local / "maisecrets-launcher" / "last-start.txt").read_text(encoding="utf-8", errors="replace")
        self.assertIn("event=user-prompt", record)
        self.assertIn(f"localappdata={local}", record)
        self.assertNotIn("no Python", record)
        self.assertNotIn('"prompt"', record)


class RunCmdMarkerTests(unittest.TestCase):
    """run.cmd without Python leaves its incident marker in %LOCALAPPDATA%\\maisecrets-launcher, where last-start.txt
    is written (docs/DIAGNOSTICS.md, section 3): no detached child, which would inherit the hook's pipe handles, the
    configured home is not touched (codex code review, round 3), and nothing is written into the plugin folder, whose
    contents Codex binds the approval of the hooks to (openai/codex#54619)."""

    def setUp(self):
        if os.name != "nt":
            self.skipTest("cmd.exe runs on Windows only; the GitHub Windows runner runs it")

    def test_without_python_the_marker_is_in_the_launcher_folder_and_the_home_is_untouched(self):
        base = Path(tempfile.mkdtemp(prefix="maisecrets-runcmd-mark-"))
        self.addCleanup(shutil.rmtree, base, True)
        (base / "hooks").mkdir()
        shutil.copyfile(RUN_CMD, base / "hooks" / "run.cmd")
        (base / "hooks" / "dispatch.py").write_text("raise SystemExit('dispatch.py ran')\n", encoding="utf-8")
        home, empty = base / "home", base / "empty"
        home.mkdir()
        empty.mkdir()
        system32 = os.path.join(os.environ["SystemRoot"], "System32")
        # no Python anywhere run.cmd looks: SystemRoot (the py launcher) and the install folders point to an empty one
        env = {"SystemRoot": str(empty), "PATH": system32, "COMSPEC": os.path.join(system32, "cmd.exe"),
               "USERPROFILE": str(base), "LOCALAPPDATA": str(empty), "ProgramFiles": str(empty),
               "MAISECRETS_HOME": str(home)}
        started = time.monotonic()
        r = subprocess.run([os.path.join(system32, "cmd.exe"), "/C", str(base / "hooks" / "run.cmd"), "post-tool"],
                           input="{}", capture_output=True, text=True, env=env, timeout=60)
        took = time.monotonic() - started
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("withheld", r.stdout)
        self.assertLess(took, 20)
        self.assertTrue((empty / "maisecrets-launcher" / "incident-marker.launcher.no-python").is_dir())
        self.assertIn("no Python", (empty / "maisecrets-launcher" / "last-start.txt").read_text(errors="replace"))
        self.assertEqual(sorted(os.listdir(base / "hooks")), ["dispatch.py", "run.cmd"], "nothing in the plugin folder")
        self.assertEqual(os.listdir(home), [], "the configured home is not touched")

    def test_without_python_each_event_refuses_in_the_form_of_each_client(self):
        # the real cmd.exe: JSON and exit 0 for every hook event; post-tool in the shape of each client
        base = Path(tempfile.mkdtemp(prefix="maisecrets-runcmd-json-"))
        self.addCleanup(shutil.rmtree, base, True)
        (base / "hooks").mkdir()
        shutil.copyfile(RUN_CMD, base / "hooks" / "run.cmd")
        (base / "hooks" / "dispatch.py").write_text("raise SystemExit('dispatch.py ran')\n", encoding="utf-8")
        empty = base / "empty"
        empty.mkdir()
        system32 = os.path.join(os.environ["SystemRoot"], "System32")
        env = {"SystemRoot": str(empty), "PATH": system32, "COMSPEC": os.path.join(system32, "cmd.exe"),
               "USERPROFILE": str(base), "LOCALAPPDATA": str(empty), "ProgramFiles": str(empty),
               "MAISECRETS_HOME": str(base / "home")}
        claude = '{"prompt": "x", "session_id": "S", "prompt_id": "p"}'
        codex = '{"prompt": "x", "session_id": "S", "turn_id": "t", "model": "m"}'
        for event in ("user-prompt", "pre-tool", "post-tool", "post-tool-failure", "session-start"):
            for name, payload in (("claude", claude), ("codex", codex)):
                with self.subTest(event=event, client=name):
                    r = subprocess.run([os.path.join(system32, "cmd.exe"), "/C", str(base / "hooks" / "run.cmd"),
                                        event], input=payload, capture_output=True, text=True, env=env, timeout=60)
                    self.assertNotIn("dispatch.py ran", r.stdout + r.stderr)
                    self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
                    out = json.loads(r.stdout)
                    if event == "post-tool" and name == "codex":
                        self.assertEqual(out.get("decision"), "block", out)
                        self.assertNotIn("hookSpecificOutput", out)
                    else:
                        assert_refuses(self, event, r)


class RunCmdClearedEnvironmentTests(unittest.TestCase):
    """Codex clears the environment of a hook and replays a snapshot (codex-rs command_runner.rs). With no
    variables at all run.cmd found no Python (exit 2, a failed hook), and with SystemRoot and PATH only, Python
    found no home directory (measured on windows-latest, 2026-09-30). The Codex form of the hook must block."""

    def setUp(self):
        if os.name != "nt":
            self.skipTest("cmd.exe runs on Windows only; the GitHub Windows runner and the e2e project run it")

    def test_the_codex_command_blocks_with_an_empty_environment_and_an_umlaut_profile(self):
        base = Path(tempfile.mkdtemp(prefix="maisecrets-empty-env-"))
        self.addCleanup(shutil.rmtree, base, True)
        profile = base / "Users" / "Tëst Adämmer (x86)"
        root = profile / ".codex" / "plugins" / "cache" / "workspace-directory" / "maisecrets" / "0.0.0"
        for d in ("hooks", "maisecrets"):
            shutil.copytree(ROOT / d, root / d)
        # the profile run.cmd derives from its own path holds the store: a temp one, never the real one
        (profile / ".maisecrets").mkdir()
        (profile / ".maisecrets" / "config.json").write_text(
            json.dumps({"backend": "jsonfile", "allow_plaintext_store": True}))
        # the Python the installer puts in Program Files for all users; the runner's Python has no other name here
        pf = Path(os.environ["ProgramFiles"]) / "Python312"
        if not (pf / "python.exe").exists():
            made = subprocess.run(f'mklink /J "{pf}" "{sys.base_prefix}"', shell=True, capture_output=True)
            if made.returncode != 0:
                self.skipTest("cmd.exe runs on Windows only; a junction in Program Files needs an administrator")
            self.addCleanup(os.rmdir, pf)
        data = json.loads((root / "hooks" / "hooks.json").read_text(encoding="utf-8"))
        line = data["hooks"]["UserPromptSubmit"][0]["hooks"][0]["commandWindows"].replace("${CLAUDE_PLUGIN_ROOT}",
                                                                                          str(root))
        payload = json.dumps({"prompt": "reach me at x" + chr(64) + "beispiel-gmbh.de", "session_id": "S",
                              "turn_id": "T", "hook_event_name": "UserPromptSubmit"})
        comspec = os.path.join(os.environ["SystemRoot"], "System32", "cmd.exe")
        r = subprocess.run(f'"{comspec}" /C "{line}"', input=payload, capture_output=True, text=True,
                           encoding="utf-8", errors="replace", env={}, timeout=120)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(json.loads(r.stdout).get("decision"), "block", r.stdout + r.stderr)


class CmdExeForwardSlashRootTests(CmdExeFailsClosedTests):
    SLASH = "/"


class BrokenImportFailsClosedTests(unittest.TestCase):
    """The entry point cannot import the plugin's code (a half-synced folder, a missing module): every
    hook event must refuse as the launcher does without Python. Exit 1 lets the prompt or the tool
    through (ops review, 2026-09-28)."""

    def test_a_broken_package_blocks_every_event(self):
        root = Path(tempfile.mkdtemp(prefix="maisecrets-broken-"))
        self.addCleanup(shutil.rmtree, root, True)
        shutil.copytree(ROOT / "hooks", root / "hooks")
        (root / "maisecrets").mkdir()
        (root / "maisecrets" / "__init__.py").write_text("raise ImportError('half-synced')\n", encoding="utf-8")
        for event in EVENTS:
            with self.subTest(event):
                r = subprocess.run([sys.executable, str(root / "hooks" / "dispatch.py"), event],
                                   input='{"prompt": "x"}', capture_output=True, text=True, timeout=30)
                self.assertIn("cannot load its own code (ImportError)", r.stdout + r.stderr)
                self.assertNotIn("half-synced", r.stdout + r.stderr, "the type only, never the message")
                assert_refuses(self, event, r)

    def test_a_broken_package_leaves_a_marker_for_the_incident_report(self):
        root = Path(tempfile.mkdtemp(prefix="maisecrets-broken-"))
        self.addCleanup(shutil.rmtree, root, True)
        shutil.copytree(ROOT / "hooks", root / "hooks")
        (root / "maisecrets").mkdir()
        (root / "maisecrets" / "__init__.py").write_text("raise ImportError('half-synced')\n", encoding="utf-8")
        home = root / "home"
        home.mkdir()
        env = dict(os.environ, MAISECRETS_HOME=str(home))
        r = subprocess.run([sys.executable, str(root / "hooks" / "dispatch.py"), "user-prompt"],
                           input='{"prompt": "x"}', capture_output=True, text=True, timeout=30, env=env)
        assert_refuses(self, "user-prompt", r)
        self.assertTrue((home / "incident-marker.launcher.import").is_dir())


class RunCmdFailsClosedTests(unittest.TestCase):
    """run.cmd cannot run on this OS; its logic is read from the file: each interpreter runs
    dispatch.py only after it passed the 3.9 probe, and without Python every hook event refuses in
    JSON with exit 0; only a CLI use of the launcher ends in exit /b 2."""

    def setUp(self):
        self.lines = [ln.strip() for ln in RUN_CMD.read_text(encoding="utf-8").splitlines()]

    def test_dispatch_runs_only_behind_a_passed_version_probe(self):
        runs = [i for i, ln in enumerate(self.lines) if "dispatch.py" in ln and not ln.startswith("rem")]
        self.assertEqual(len(runs), 5, "py -3, python, python3, the py launcher, a python.org install folder")
        for i in runs:
            interp = self.lines[i].split('"%HERE%dispatch.py"')[0].strip()
            self.assertEqual(self.lines[i - 1], "if not errorlevel 1 (", self.lines[i])
            self.assertEqual(self.lines[i - 2],
                             f'{interp} -c "import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)" >nul 2>&1')
            self.assertEqual(self.lines[i + 1], "goto :done")

    def branch(self, label: str) -> list[str]:
        start = self.lines.index(label)
        end = next(i for i in range(start + 1, len(self.lines)) if self.lines[i].startswith(":"))
        return [ln for ln in self.lines[start + 1:end] if not ln.startswith("rem")]

    def test_without_python_every_hook_event_answers_json_and_exit_0(self):
        # exit 2 is a block in Claude Code only; Codex runs the tool on it (codex code review, 2026-10-09)
        events = {"post-tool-failure": ":np_post_tool_failure", "post-tool": ":np_post_tool",
                  "pre-tool": ":np_pre_tool", "user-prompt": ":np_user_prompt", "session-start": ":np_session_start"}
        for event, label in events.items():
            with self.subTest(event):
                self.assertIn(f'if "%~1"=="{event}" goto {label}', self.lines)
        claude = []
        for label in (":np_post_tool_failure", ":np_post_tool", ":np_pre_tool", ":np_user_prompt",
                      ":np_session_start", ":np_post_tool_codex"):
            with self.subTest(label):
                body = self.branch(label)
                (echo,) = [ln for ln in body if ln.startswith("echo ")]
                self.assertEqual(body[-2:], ["call :mark", "exit /b 0"])
                claude.append(json.loads(echo[len("echo "):]))
        failure, post, pre, prompt, session, post_codex = claude
        self.assertIn("systemMessage", failure)
        self.assertEqual(set(post), {"hookSpecificOutput"}, "Claude Code's shape only")
        self.assertIn("withheld", post["hookSpecificOutput"]["updatedToolOutput"])
        self.assertEqual(post_codex, {"decision": "block", "reason": post_codex["reason"]}, "Codex's shape only")
        self.assertIn("withheld", post_codex["reason"])
        self.assertEqual(pre["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertEqual(prompt["decision"], "block")
        self.assertIn("systemMessage", session)
        # the Codex branch is taken on the same test as run.sh: "turn_id" in the payload
        self.assertIn('findstr /l /c:"\\"turn_id\\"" >nul 2>&1', self.lines)
        # only a CLI use of the launcher still ends in exit 2, after its reason on stderr
        main = self.lines[:self.lines.index(":mark")]
        cli = main[main.index('if "%~1"=="session-start" goto :np_session_start') + 1:]
        cli = [ln for ln in cli if not ln.startswith("rem")]
        self.assertTrue(cli[0].startswith("echo maisecrets needs Python 3.9") and cli[0].endswith("1>&2"), cli[0])
        self.assertEqual(cli[1:3], ["call :mark", "exit /b 2"])
        exits = [ln for ln in main if ln.startswith("exit ")]
        self.assertEqual(sorted(set(exits)), ["exit /b %errorlevel%", "exit /b 0", "exit /b 2"], "no other way out")
        self.assertEqual(exits.count("exit /b 2"), 1)
        # the marker subroutine (docs/DIAGNOSTICS.md, section 3) runs after each answer and only returns
        mark = self.lines[self.lines.index(":mark"):]
        self.assertTrue(all(ln == "exit /b 0" for ln in mark if ln.startswith("exit ")), mark)
        self.assertEqual(sum(1 for ln in main if ln == "call :mark"), 7, "every branch leaves the marker")


def _forms(value: str) -> list[str]:
    """The byte forms a value takes in a JSONL transcript: plain, JSON-escaped, doubly escaped."""
    once = json.dumps(value)[1:-1]
    return list(dict.fromkeys([value, once, json.dumps(once)[1:-1]]))


class TranscriptScrubThroughTheHooksTests(unittest.TestCase):
    """THREAT-MODEL C3: every form of a value is masked in the client's transcript. Each case runs
    the real hook through hooks/dispatch.py on a real transcript file; nothing is mocked. A
    record the client writes AFTER the hook returned is scrubbed by the detached child."""

    def setUp(self):
        self.sb = Sandbox(JSONFILE, backend="jsonfile")
        self.addCleanup(self.sb.remove)
        self.path = self.sb.root / "transcript.jsonl"

    def write(self, *records: dict) -> None:
        with open(self.path, "a", encoding="utf-8") as f:
            for rec in records:
                f.write(json.dumps(rec) + "\n")

    def hook(self, event: str, payload: dict) -> dict:
        r = self.sb.run(event, stdin=json.dumps({**payload, "transcript_path": str(self.path)}))
        self.assertEqual(r.returncode, 0, r.stderr)
        return json.loads(r.stdout)

    def assert_scrubbed(self, value: str, keep: str, wait: float = 0.0) -> None:
        deadline = time.time() + wait
        while True:
            data = self.path.read_text(encoding="utf-8")
            left = [f for f in _forms(value) if f in data]
            if not left or time.time() >= deadline:
                break
            time.sleep(0.05)
        self.assertEqual(left, [], "a form of the value is still in the transcript")
        self.assertIn(keep, data, "the scrub masks the value only")
        for line in data.splitlines():
            json.loads(line)          # every record stays valid JSON

    def test_c1_a_blocked_prompt_is_masked_in_an_old_and_in_the_late_record(self):
        value = fake_value("Tp")
        prompt = f"password: {value}"
        self.write({"type": "user", "message": {"content": prompt}, "note": "earlier"})
        ino = os.stat(self.path).st_ino
        out = self.hook("user-prompt", {"prompt": prompt, "session_id": "S1", "prompt_id": "p1"})
        self.assertEqual(out["decision"], "block")
        self.assert_scrubbed(value, "earlier")                       # the inline scrub, before the answer
        self.write({"type": "user", "message": {"content": prompt}, "note": "late"})
        self.assert_scrubbed(value, "late", wait=5.0)                 # the detached child
        self.assertEqual(os.stat(self.path).st_ino, ino, "in place: same inode")

    def test_codex_post_tool_masks_the_raw_output_in_the_rollout(self):
        value = fake_value("Cx")
        output = f"api_key={value}\n"
        # Codex writes the raw command output into its rollout before the hook runs
        self.write({"type": "event_msg", "payload": {"type": "exec_command_end", "stdout": output}, "note": "raw"})
        out = self.hook("post-tool", {"tool_name": "Bash", "session_id": "S1", "turn_id": "t1", "model": "m",
                                      "tool_input": {"command": "cat .env"}, "tool_response": {"stdout": output}})
        self.assertEqual(out["decision"], "block")
        self.assertNotIn(value, json.dumps(out))
        self.assert_scrubbed(value, "raw")

    def test_an_mcp_resolve_masks_the_hook_answer_the_client_records(self):
        # a value with a quote and a backslash, so its escaped forms differ from the plain one
        value = 'Mq"' + fake_value("M") + "\\z"
        r = self.sb.run("put", stdin=value)
        key = re.search(r"placeholder (?:is )?\u27e6(\w+)", r.stdout).group(1)
        ref = f"⟦{key}⟧"
        self.hook("user-prompt", {"prompt": f"use {ref}", "session_id": "S1", "prompt_id": "p1"})   # admits S1
        out = self.hook("pre-tool", {"tool_name": "mcp__srv__echo", "session_id": "S1", "prompt_id": "p2",
                                     "tool_input": {"token": ref}})
        self.assertEqual(out["hookSpecificOutput"]["updatedInput"], {"token": value})
        # Claude Code records the hook's stdout as a hook_success attachment: doubly escaped
        self.write({"type": "attachment", "attachment": {"type": "hook_success", "stdout": json.dumps(out)},
                    "note": "attachment"},
                   {"type": "assistant", "content": [{"type": "tool_use", "input": {"token": value}}]})
        data = self.path.read_text(encoding="utf-8")
        self.assertTrue(all(f in data for f in _forms(value)[1:]), "the record carries the escaped forms")
        self.assert_scrubbed(value, "attachment", wait=5.0)


class _RefusingStore:
    """A store that holds one item and refuses to let it go, the way a locked keychain does
    (RuntimeError) or a file store in a folder that is not writable (PermissionError)."""
    test_mode = False

    def __init__(self, exc: BaseException) -> None:
        self.exc = exc

    def wipe(self) -> int:
        raise self.exc

    def keys(self) -> list[str]:
        return ["SECRET_c1"]

    def get(self, key: str) -> str | None:
        return "x" if key == "SECRET_c1" else None

    def delete(self, key: str) -> None:
        raise self.exc


class RefusedWipeTests(unittest.TestCase):
    """README: `wipe` reports when an item refused to go. The CLI must say so and exit non-zero,
    never print a clean "wiped" alone."""

    def wipe(self, store: object) -> tuple[int, str]:
        import contextlib
        import io
        from unittest import mock
        from maisecrets import cli, vault
        buf = io.StringIO()
        with mock.patch.object(vault, "make_backend", lambda cfg: store), contextlib.redirect_stdout(buf):
            rc = cli.main(["wipe", "--yes"])
        return rc, buf.getvalue()

    def test_a_locked_store_is_reported_and_the_exit_code_says_so(self):
        rc, out = self.wipe(_RefusingStore(RuntimeError("locked")))
        self.assertEqual(rc, 1, out)
        self.assertIn("NOT complete: store: RuntimeError; store item SECRET_c1 not deleted.", out)
        self.assertIn("A value may still be in the store; check it by hand.", out)

    def test_a_file_store_that_cannot_be_written_is_reported_not_a_traceback(self):
        # the file stores raise OSError, not RuntimeError: a folder without write permission
        # ended the wipe with a PermissionError traceback and no "NOT complete" (2026-09-27)
        rc, out = self.wipe(_RefusingStore(PermissionError(13, "Permission denied")))
        self.assertEqual(rc, 1, out)
        self.assertIn("NOT complete: store: PermissionError; store item SECRET_c1 not deleted.", out)

    def test_an_encrypted_file_that_does_not_go_is_not_counted_as_wiped(self):
        from unittest import mock
        from maisecrets import vault
        store = vault.EncryptedFileBackend.__new__(vault.EncryptedFileBackend)
        store.path = Path(self.sb_home()) / "vault.enc.json"
        store.key_file = store.path.with_name("key")
        store.path.write_text('{"SECRET_c1": "x"}', encoding="utf-8")
        with mock.patch.object(Path, "unlink", side_effect=PermissionError(13, "Permission denied")):
            with self.assertRaises(RuntimeError, msg="a wipe that deleted nothing must not return a count"):
                store.wipe()

    def sb_home(self) -> str:
        sb = Sandbox(JSONFILE, backend="jsonfile")
        self.addCleanup(sb.remove)
        return str(sb.home)


# loaded by every Python the hook starts (PYTHONPATH): each way out to the network writes the
# tripwire and raises, so an attempt fails the test even when the hook swallowed the error
_NET_TRIPWIRE = '''
import os, socket, http.client, urllib.request

def _trip(what):
    def refuse(*a, **kw):
        with open(os.environ["MS_TEST_TRIPWIRE"], "a") as f:
            f.write("network: %s %r\\n" % (what, a[1:2] or a[:1]))
        raise OSError("maisecrets test: no network")
    return refuse

socket.socket.connect = _trip("socket.connect")
socket.socket.connect_ex = _trip("socket.connect_ex")
socket.socket.sendto = _trip("socket.sendto")
socket.create_connection = _trip("socket.create_connection")
socket.getaddrinfo = _trip("socket.getaddrinfo")
http.client.HTTPConnection.connect = _trip("http.client.connect")
urllib.request.urlopen = _trip("urllib.request.urlopen")
'''


def _payloads(ref: str) -> list[tuple[str, dict]]:
    """One payload per hook event, each one on the path that does the most work."""
    value = fake_value("Nw")
    return [
        ("session-start", {"transcript_path": ""}),
        ("user-prompt", {"prompt": f"password: {value}", "session_id": "S1", "prompt_id": "p1"}),
        ("user-prompt", {"prompt": f"use {ref}", "session_id": "S1", "prompt_id": "p2"}),
        ("pre-tool", {"tool_name": "Bash", "tool_input": {"command": f"printf %s {ref}"}, "session_id": "S1",
                      "prompt_id": "p3"}),
        ("pre-tool", {"tool_name": "mcp__srv__echo", "tool_input": {"token": ref}, "session_id": "S1",
                      "prompt_id": "p4"}),
        ("post-tool", {"tool_name": "Bash", "session_id": "S1", "prompt_id": "p5",
                       "tool_response": {"stdout": f"api_key={fake_value('Po')}"}}),
        ("post-tool", {"tool_name": "Bash", "session_id": "S1", "turn_id": "t", "model": "m",
                       "tool_response": {"stdout": f"api_key={fake_value('Pc')}"}}),
    ]


class NoNetworkTests(unittest.TestCase):
    """PRIVACY.md: no hook opens a network connection."""

    def test_no_hook_entry_point_reaches_for_the_network_as_a_subprocess(self):
        sb = Sandbox(JSONFILE, backend="jsonfile")
        self.addCleanup(sb.remove)
        site = sb.root / "site"
        site.mkdir()
        # only the first sitecustomize on the path runs: this one carries the platform fakes of
        # tests/_isolate.py too
        fakes = Path(_isolate.SITE, "sitecustomize.py").read_text(encoding="utf-8")
        (site / "sitecustomize.py").write_text(_NET_TRIPWIRE + "\n" + fakes, encoding="utf-8")
        env = sb.env(PYTHONPATH=str(site))
        # the tripwire itself must work, or a green run proves nothing
        probe = subprocess.run([sys.executable, "-c", "import socket; socket.create_connection(('192.0.2.1', 9))"],
                               env=env, capture_output=True, text=True, timeout=30)
        self.assertIn("no network", probe.stderr)
        (sb.root / "tripwire").unlink()
        out = sb.run("put", stdin=fake_value("Rf"), env=env).stdout
        key = re.search(r"placeholder (?:is )?\u27e6(\w+)", out).group(1)
        transcript = sb.root / "t.jsonl"
        transcript.write_text("{}\n", encoding="utf-8")
        for event, payload in _payloads(f"⟦{key}⟧"):
            with self.subTest(event):
                # Sandbox.run fails the test when the tripwire file exists
                r = sb.run(event, stdin=json.dumps({**payload, "transcript_path": str(transcript)}), env=env)
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertNotIn("Traceback", r.stderr)
        r = sb.run(key, "--grant", "x" * 22, env=env, script=ROOT / "hooks" / "resolve.py")
        self.assertIn("no-grant", r.stderr)

    def test_no_hook_reaches_for_the_network_in_process(self):
        # the pre-tool payload serves a value that nobody reads: take it back after the test, or its
        # serving child waits 120 s and the next module that counts children finds it (2026-09-27)
        _hygiene.watch_children(self)
        import socket
        import http.client
        import urllib.request
        from unittest import mock
        from maisecrets import hooks
        from maisecrets.vault import Vault
        tried: list[str] = []

        def refuse(what):
            def f(*a, **kw):
                tried.append(what)
                raise OSError("no network")
            return f
        e = Vault().put(fake_value("Ip"), "SECRET", "manual", session="S1")
        handlers = {"user-prompt": hooks.user_prompt, "pre-tool": hooks.pre_tool, "post-tool": hooks.post_tool}
        with mock.patch.object(socket.socket, "connect", refuse("connect")), \
                mock.patch.object(socket.socket, "connect_ex", refuse("connect_ex")), \
                mock.patch.object(socket, "create_connection", refuse("create_connection")), \
                mock.patch.object(socket, "getaddrinfo", refuse("getaddrinfo")), \
                mock.patch.object(http.client.HTTPConnection, "connect", refuse("http")), \
                mock.patch.object(urllib.request, "urlopen", refuse("urlopen")), \
                mock.patch.object(hooks, "_clipboard", lambda text: False):
            for event, payload in _payloads(e.ref):
                if event in handlers:
                    with self.subTest(event):
                        self.assertIsInstance(handlers[event](dict(payload, transcript_path="")), dict)
        self.assertEqual(tried, [])


if __name__ == "__main__":
    unittest.main()


class CodexShapedRefusalTests(unittest.TestCase):
    """Codex reads PostToolUse through a strict schema: an answer with Claude's updatedToolOutput is
    dropped as a whole, and the output reaches the model (Codex review, 2026-09-28). Each fail-closed
    path answers a Codex payload (turn_id) with decision/reason only."""

    CODEX_PAYLOAD = '{"turn_id": "t", "model": "m", "tool_name": "Bash", "tool_response": {"stdout": "x"}}'

    def check(self, r: subprocess.CompletedProcess) -> None:
        self.assertEqual(r.returncode, 0, r.stderr)
        out = json.loads(r.stdout)
        self.assertEqual(set(out), {"decision", "reason"}, out)
        self.assertEqual(out["decision"], "block")
        self.assertIn("withheld", out["reason"])

    @unittest.skipIf(_NO_POSIX_SH, _POSIX_ONLY)
    def test_a_missing_launcher_answers_codex_in_its_shape(self):
        data = json.loads((ROOT / "hooks" / "hooks.json").read_text(encoding="utf-8"))
        command = next(h["command"] for g in data["hooks"]["PostToolUse"] for h in g["hooks"])
        env = {k: v for k, v in os.environ.items() if not k.startswith("CLAUDE")}
        env["CLAUDE_PLUGIN_ROOT"] = str(Path(tempfile.mkdtemp(prefix="maisecrets-moved-")) / "gone")
        self.check(subprocess.run(["sh", "-c", command], input=self.CODEX_PAYLOAD, capture_output=True, text=True,
                                  env=env, timeout=30))

    def test_a_broken_import_answers_codex_in_its_shape(self):
        root = Path(tempfile.mkdtemp(prefix="maisecrets-broken-"))
        self.addCleanup(shutil.rmtree, root, True)
        shutil.copytree(ROOT / "hooks", root / "hooks")
        (root / "maisecrets").mkdir()
        (root / "maisecrets" / "__init__.py").write_text("raise ImportError('x')\n", encoding="utf-8")
        self.check(subprocess.run([sys.executable, str(root / "hooks" / "dispatch.py"), "post-tool"],
                                  input=self.CODEX_PAYLOAD, capture_output=True, text=True, timeout=30))
