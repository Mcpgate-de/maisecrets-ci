"""An older maisecrets in another session (maisecrets/older_versions.py): versions.json notes each version's session
start and gateway renewal; the session start of the newest version says once a day that an older one still runs,
where a gateway login is in use; /maisecrets:status says it each time. A version before the marker is seen by its
events.log lines.

Run: python3 -m unittest tests.test_older_versions -v
"""
from __future__ import annotations

import json
import os
import sys
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets import older_versions as ov, status_verdict as sv  # noqa: E402

NOW = time.mktime((2026, 11, 19, 12, 0, 0, 0, 0, -1))
HOUR = 3600.0
CUR = "0.9.20"


class _Base(unittest.TestCase):
    def setUp(self):
        for f in (ov.MARKER, ov.EVENTS, ov.INFLIGHT):
            f.unlink(missing_ok=True)
            self.addCleanup(f.unlink, missing_ok=True)
        p = mock.patch.object(ov, "_current", lambda: CUR)
        p.start()
        self.addCleanup(p.stop)

    def marker(self, versions: dict, **extra) -> None:
        ov.MARKER.write_text(json.dumps({"versions": versions, **extra}), encoding="utf-8")

    def gateway(self) -> None:
        ov.INFLIGHT.write_text("{}", encoding="utf-8")

    def events(self, *lines) -> None:
        ov.EVENTS.write_text("".join(json.dumps({"ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(t)),
                                                 "hook": "PostToolUse", "client": "claude", "version": v,
                                                 "hits": [{"key": "SECRET_c1", "type": "SECRET", "kind": "secret"}]})
                                     + "\n" for v, t in lines), encoding="utf-8")


class MarkerTests(_Base):
    def test_a_session_start_and_a_renewal_write_the_version_and_times_only(self):
        ov.mark_run("start", NOW)
        ov.mark_run("refresh", NOW + 5)
        ov.mark_run("prompt", NOW + 9)                         # no other kind is written
        data = json.loads(ov.MARKER.read_text(encoding="utf-8"))
        self.assertEqual(data, {"versions": {CUR: {"first": NOW, "start": NOW, "refresh": NOW + 5}}})
        self.assertEqual(ov.start(NOW + 10), None, "the first start of a version sees nothing older")
        self.assertEqual(json.loads(ov.MARKER.read_text())["versions"][CUR]["first"], NOW, "first stays")

    def test_a_damaged_marker_is_read_as_empty_and_written_new(self):
        ov.MARKER.write_text("{not json", encoding="utf-8")
        self.assertIsNone(ov.start(NOW))
        self.assertEqual(json.loads(ov.MARKER.read_text())["versions"][CUR]["start"], NOW)

    def test_a_version_with_no_run_for_30_days_leaves_the_marker(self):
        self.marker({"0.9.10": {"first": NOW - 40 * 86400, "start": NOW - 31 * 86400}})
        ov.mark_run("start", NOW)
        self.assertEqual(list(json.loads(ov.MARKER.read_text())["versions"]), [CUR])


class WarningTests(_Base):
    def setUp(self):
        super().setUp()
        self.gateway()

    def test_an_older_renewal_after_the_update_is_named_once_a_day(self):
        self.marker({CUR: {"first": NOW - 5 * HOUR, "start": NOW - 5 * HOUR},
                     "0.9.15": {"first": NOW - 9 * 86400, "start": NOW - 3 * 86400, "refresh": NOW - HOUR}})
        day = time.strftime("%Y-%m-%d %H:%M", time.localtime(NOW - 5 * HOUR))
        line = ("maisecrets: An older maisecrets (0.9.15) ran in the last day and may still be open in another "
                "session. Its gateway renewals can end your login. Restart the sessions that started before "
                f"{day}.")
        self.assertEqual(ov.start(NOW), line)
        self.assertIsNone(ov.start(NOW + HOUR), "once a day")
        self.assertEqual(ov.status(NOW + HOUR), ("0.9.15", line[len("maisecrets: "):]), "the status says it each time")
        self.assertIsNone(ov.start(NOW + 2 * 86400), "past the window: nothing")
        self.marker({CUR: {"first": NOW - 5 * HOUR}, "0.9.15": {"refresh": NOW + 86400 - HOUR}}, told="2026-11-19")
        self.assertIsNotNone(ov.start(NOW + 86400), "the next day again")

    def test_a_version_before_the_marker_is_seen_by_its_events_lines(self):
        self.marker({CUR: {"first": NOW - 5 * HOUR, "start": NOW - 5 * HOUR}})
        self.events(("0.9.14", NOW - 6 * HOUR), (CUR, NOW - 2 * HOUR))
        self.assertIsNone(ov.start(NOW), "a line before the update says nothing")
        self.events(("0.9.14", NOW - 6 * HOUR), ("0.9.13", NOW - 3 * HOUR), ("0.9.14", NOW - 2 * HOUR))
        self.marker({CUR: {"first": NOW - 5 * HOUR}})
        self.assertIn("An older maisecrets (0.9.13) ran", ov.start(NOW), "the oldest one is named")

    def test_nothing_is_said_without_a_reason(self):
        cases = [
            # an older start before this version's first start: a session that may be closed
            {CUR: {"first": NOW - 5 * HOUR}, "0.9.15": {"start": NOW - 6 * HOUR}},
            # an older run longer ago than the window
            {CUR: {"first": NOW - 3 * 86400}, "0.9.15": {"refresh": NOW - 2 * 86400}},
            # a newer version in another session
            {CUR: {"first": NOW - 5 * HOUR}, "0.9.21": {"refresh": NOW - HOUR}},
            # a version that is no version
            {CUR: {"first": NOW - 5 * HOUR}, "dev": {"refresh": NOW - HOUR}},
        ]
        for versions in cases:
            self.marker(versions)
            self.assertIsNone(ov.start(NOW), versions)
            self.assertIsNone(ov.status(NOW), versions)

    def test_without_a_gateway_login_nothing_is_said(self):
        ov.INFLIGHT.unlink()
        self.marker({CUR: {"first": NOW - 5 * HOUR}, "0.9.15": {"start": NOW - HOUR}})
        self.assertIsNone(ov.start(NOW))
        self.marker({CUR: {"first": NOW - 5 * HOUR}, "0.9.15": {"start": NOW - HOUR, "refresh": NOW - 2 * HOUR}})
        self.assertIsNotNone(ov.start(NOW), "a renewal in the marker is a gateway login")

    def test_the_status_check_is_a_warn_with_the_sentence(self):
        self.marker({CUR: {"first": NOW - 5 * HOUR}, "0.9.15": {"refresh": NOW - HOUR}})
        with mock.patch.object(ov.time, "time", lambda: NOW):
            check = sv.older_verdict()
        self.assertEqual((check.state, check.name, check.fact), ("warn", "older", "0.9.15 ran in 24 h"))
        self.assertIn("Restart the sessions that started before", check.detail)
        self.assertLessEqual(len(check.fact), sv.FACT_COL)
        self.assertNotIn("told", json.loads(ov.MARKER.read_text()), "the status marks nothing")


class RaceTests(unittest.TestCase):
    """An old version's renewal and a new version's start at once: neither erases the other (Gate A of !591)."""

    def test_two_processes_that_mark_at_once_keep_both_times(self):
        import subprocess
        ov.MARKER.unlink(missing_ok=True)
        self.addCleanup(ov.MARKER.unlink, missing_ok=True)
        code = ("import sys\nsys.path.insert(0, sys.argv[1])\nfrom maisecrets import older_versions as ov\n"
                "ov._current = lambda: sys.argv[2]\nfor i in range(150):\n    ov.mark_run(sys.argv[3], 1000.0 + i)\n")
        env = {k: v for k, v in os.environ.items() if not k.startswith(("CODEX_", "CLAUDE"))}
        procs = [subprocess.Popen([sys.executable, "-c", code, str(ROOT), version, kind], env=env)
                 for version, kind in (("0.9.15", "refresh"), ("0.9.20", "start"))]
        for proc in procs:
            self.assertEqual(proc.wait(timeout=120), 0)
        versions = json.loads(ov.MARKER.read_text(encoding="utf-8"))["versions"]
        self.assertEqual(versions["0.9.15"].get("refresh"), 1149.0, "the old renewal is kept")
        self.assertEqual(versions["0.9.20"].get("start"), 1149.0, "the new start is kept")

    def test_a_time_another_process_wrote_later_stays(self):
        ov.MARKER.write_text(json.dumps({"versions": {"0.9.15": {"first": 10.0, "refresh": 500.0}}}), encoding="utf-8")
        self.addCleanup(ov.MARKER.unlink, missing_ok=True)
        with mock.patch.object(ov, "_current", lambda: "0.9.15"):
            ov.mark_run("refresh", 400.0)
        self.assertEqual(json.loads(ov.MARKER.read_text())["versions"]["0.9.15"], {"first": 10.0, "refresh": 500.0})


class SessionStartTests(unittest.TestCase):
    """The real session-start hook, twice: the line once, for the person only."""

    def test_the_session_start_hook_shows_the_line_once(self):
        import subprocess
        import tempfile
        for f in (ov.MARKER, ov.EVENTS, ov.INFLIGHT):
            f.unlink(missing_ok=True)
            self.addCleanup(f.unlink, missing_ok=True)
        cur = ov._current()
        mine = ov._tuple(cur)
        older = ".".join(map(str, mine[:2] + (mine[2] - 1,))) if mine[2] else "0.0.1"
        now = time.time()
        ov.MARKER.write_text(json.dumps({"versions": {cur: {"first": now - 5 * HOUR},
                                                      older: {"refresh": now - HOUR}}}), encoding="utf-8")
        ov.INFLIGHT.write_text("{}", encoding="utf-8")
        env = {k: v for k, v in os.environ.items() if not k.startswith(("GIT_", "CODEX_", "CLAUDE"))}
        env["TMPDIR"] = tempfile.gettempdir()
        payload = json.dumps({"session_id": "SS", "transcript_path": "", "source": "startup"})
        entry = "session" + "-start"
        runs = [subprocess.run([sys.executable, str(ROOT / "hooks" / "dispatch.py"), entry], input=payload,
                               capture_output=True, text=True, env=env, timeout=60, cwd=tempfile.gettempdir())
                for _ in range(2)]
        first, second = (json.loads(r.stdout) for r in runs)
        self.assertIn(f"An older maisecrets ({older}) ran in the last day", first.get("systemMessage", ""))
        self.assertNotIn("An older maisecrets", second.get("systemMessage", ""), "once a day")
        self.assertNotIn("older maisecrets", first["hookSpecificOutput"]["additionalContext"], "for the person only")
        self.assertIn("start", json.loads(ov.MARKER.read_text())["versions"][cur], "the start is noted")


if __name__ == "__main__":
    unittest.main()
