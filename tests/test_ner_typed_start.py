"""`ner local`, typed by the person, starts the name service at once (no question first, 0.9.19), by the start of
`run.sh ner start` in the background; a setting of a policy or of an earlier session never starts a download.
`ner off` turns the source off as in 0.9.18; a start that still runs ends by itself, and the answer says so.

Docker is a fake shell script on PATH (POSIX only: on Windows the fake would need a .cmd of its own), and the probe of
127.0.0.1:8765 is a fake too, so a real container of the person on that port changes nothing."""
from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one
from _hygiene import CLAUDE  # noqa: E402

from maisecrets import hooks, ner_setup  # noqa: E402
from maisecrets.vault import HOME  # noqa: E402

CONFIG = {"backend": "jsonfile", "allow_plaintext_store": True}
CID = "feed" * 16
# the fake docker: every call goes into the log; `run` waits (the download) until the test writes the file `die`
FAKE = r"""#!/bin/sh
echo "$*" >> "$FAKE_DOCKER_LOG"
D="$FAKE_DOCKER_DIR"
case "$1" in
  info) exit 1 ;;
  container) echo "no such container" >&2; exit 1 ;;
  run) i=0; while [ $i -lt 600 ]; do [ -f "$D/die" ] && break; sleep 0.1; i=$((i+1)); done; echo "%(cid)s" ;;
esac
exit 0
""" % {"cid": CID}


def _prompt(text: str) -> dict:
    return hooks.user_prompt({"prompt": text, "session_id": "S1", **CLAUDE})


@unittest.skipIf(os.name == "nt", "the fake docker is a shell script")
class TypedStartTests(unittest.TestCase):
    def setUp(self):
        Path(HOME, "config.json").write_text(json.dumps(CONFIG), encoding="utf-8")
        self.dir = tempfile.mkdtemp(prefix="fake-docker-")
        self.log = Path(self.dir, "calls.log")
        self.log.write_text("", encoding="utf-8")
        tool = Path(self.dir, "docker")
        tool.write_text(FAKE, encoding="utf-8")
        tool.chmod(tool.stat().st_mode | stat.S_IXUSR)
        env = {"PATH": self.dir + os.pathsep + os.environ.get("PATH", ""), "FAKE_DOCKER_LOG": str(self.log),
               "FAKE_DOCKER_DIR": self.dir}
        # each start this test spawns is kept, so the cleanup waits for it and reaps it: none outlives the test
        import subprocess
        real, self.spawned = subprocess.Popen, []

        def popen(argv, *a, **k):
            p = real(argv, *a, **k)
            if "maisecrets.cli" in argv:
                self.spawned.append(p)
            return p
        for p in (mock.patch.dict(os.environ, env), mock.patch.object(ner_setup, "probe", return_value=(False, "")),
                  mock.patch.object(ner_setup.subprocess, "Popen", popen)):
            p.start()
            self.addCleanup(p.stop)
        os.environ.pop(ner_setup.NO_START_ENV, None)
        self.addCleanup(self._clean)

    def _clean(self):
        # the fake download ends, and with it the start; each start is reaped, or its group is killed
        import signal
        import subprocess
        Path(self.dir, "die").write_text("", encoding="utf-8")
        for p in self.spawned:
            try:
                p.wait(timeout=20)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(p.pid, signal.SIGKILL)
                except OSError:
                    pass
                p.wait()
        self.wait_for(lambda: not ner_setup.start_running(), 20)
        Path(HOME, ner_setup.START_LOG).unlink(missing_ok=True)
        Path(HOME, "config.json").write_text(json.dumps(CONFIG), encoding="utf-8")

    def calls(self) -> list:
        return self.log.read_text(encoding="utf-8").splitlines()

    def wait_for(self, cond, seconds=20.0):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            if cond():
                return True
            time.sleep(0.05)
        return False

    def test_typed_local_starts_without_a_question_once_and_off_says_that_it_still_runs(self):
        out = _prompt("/maisecrets:ner local")
        # a success: the slash command runs on (the hook path of Codex and claude -p), with the note of the start
        self.assertIn(ner_setup.START_NOTE, out["hookSpecificOutput"]["additionalContext"])
        self.assertTrue(self.wait_for(lambda: any(c.startswith("run ") for c in self.calls())), self.calls())
        self.assertIn("mcpgate/ner", [c for c in self.calls() if c.startswith("run ")][0])
        self.assertTrue(ner_setup.start_running())
        # a second typed choice while it runs starts no second one
        _prompt("/maisecrets:ner local")
        time.sleep(1.0)
        self.assertEqual(len([c for c in self.calls() if c.startswith("run ")]), 1, self.calls())
        # off turns the source off; the start that runs ends by itself, and the answer says so
        out = _prompt("/maisecrets:ner off")
        self.assertIn(ner_setup.STILL_RUNS, json.dumps(out))
        self.assertFalse([c for c in self.calls() if c.startswith(("rm ", "stop ", "kill "))], self.calls())

    def test_off_with_no_start_says_nothing_about_a_start(self):
        _prompt("/maisecrets:ner local")
        Path(self.dir, "die").write_text("", encoding="utf-8")
        self.assertTrue(self.wait_for(lambda: not ner_setup.start_running()))
        out = _prompt("/maisecrets:ner off")
        self.assertNotIn("still runs", json.dumps(out))

    def test_a_spawn_that_fails_starts_nothing(self):
        with mock.patch.object(ner_setup.subprocess, "Popen", side_effect=OSError("no python")):
            self.assertFalse(ner_setup.start_typed("slash command"))

    def test_a_setting_alone_never_starts_a_download(self):
        # the setting is local (a policy or an earlier session), and no container exists
        Path(HOME, "config.json").write_text(json.dumps({**CONFIG, "remote_detector": {"url": ner_setup.LOCAL_URL}}),
                                             encoding="utf-8")
        tool = ner_setup.container_tool()
        self.assertEqual(ner_setup.follow_pin(tool), "none")       # what the session start runs in the background
        with mock.patch.object(ner_setup.subprocess, "Popen") as popen:
            # the session start says that nothing starts: the start line names /maisecrets:ner local
            self.assertFalse(ner_setup.restart_local({"url": ner_setup.LOCAL_URL}))
        popen.assert_called_once()
        # only a typed route starts it
        for route in ("session start", "policy", "cli", ""):
            self.assertFalse(ner_setup.start_typed(route), route)
        self.assertFalse(ner_setup.start_running())
        self.assertFalse([c for c in self.calls() if c.startswith(("run ", "pull "))], self.calls())

    def test_the_start_line_names_the_command_that_starts_it(self):
        from maisecrets import ner_health
        fact, step = ner_health.fact_and_step("local_down", {"url": ner_setup.LOCAL_URL})
        self.assertIn("not running", fact)
        self.assertIn("/maisecrets:ner local", step)


if __name__ == "__main__":
    unittest.main()
