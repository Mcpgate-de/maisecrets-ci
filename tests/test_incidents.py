"""The local incident record (maisecrets/incidents.py, docs/DIAGNOSTICS.md): closed values only, bounded, markers
that follow nothing, one form function for the CLI and the prompt hook, a report that sends nothing.

Run: python3 -m unittest tests.test_incidents -v
"""
from __future__ import annotations

import os
import shutil
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

from maisecrets import incidents  # noqa: E402

TODAY = time.strftime("%Y-%m-%d")


def item(**kw) -> dict:
    base = {"code": "store.lock", "cause": "lock", "class": "fail-closed", "event": "UserPromptSubmit",
            "tool_class": "-", "client": "claude"}
    base.update(kw)
    return base


def group(**kw) -> dict:
    base = {"code": "store.lock", "cause": "lock", "class": "fail-closed", "event": "UserPromptSubmit",
            "tool_class": "-", "client": "claude", "days": [TODAY], "count": 1, "plugin_version": "0.6.10"}
    base.update(kw)
    return base


class _Home(unittest.TestCase):
    def setUp(self):
        self.home = Path(tempfile.mkdtemp(prefix="maisecrets-incidents-"))
        self.addCleanup(lambda: shutil.rmtree(self.home, ignore_errors=True))
        p = mock.patch.dict(os.environ, {"MAISECRETS_HOME": str(self.home)})
        p.start()
        self.addCleanup(p.stop)
        incidents.discard()


class SchemaTests(unittest.TestCase):
    def test_a_valid_group_keeps_only_its_closed_fields(self):
        g = incidents.valid_group(dict(group(), extra="a path /home/someone", number_kind="errno", number=13))
        self.assertEqual(g["number"], 13)
        self.assertNotIn("extra", g)

    def test_each_hostile_form_drops_the_whole_group(self):
        hostile = {
            "code": ["store.lock\n", "store.lоck", "x" * 200, None, 1],
            "cause": ["Lock", "lock ", ""],
            "number": [5000, -1, True, 1.5, float("nan"), "13"],
            "class": ["fail closed"],
            "event": ["Bash", "UserPromptSubmit​"],
            "tool_class": ["mcp__server__tool"],
            "client": ["claude-code"],
            "days": [[], ["2026-02-30"], ["1999-01-01"], ["2999-01-01"], [TODAY, TODAY], [TODAY] * 8, "x",
                     [{"d": TODAY}]],
            "count": [0, 10000, True, 2.0, "3"],
            "plugin_version": ["0.6.10-dev", "01.2.3", "1.2", "1.2.3 /x", 1],
        }
        for field, values in hostile.items():
            for v in values:
                with self.subTest(field=field, value=v):
                    g = group(number_kind="errno", number=13)
                    g[field] = v
                    self.assertIsNone(incidents.valid_group(g))

    def test_a_number_needs_its_kind_and_stays_in_the_kind_range(self):
        self.assertIsNone(incidents.valid_group(group(number=1)))
        self.assertIsNone(incidents.valid_group(group(number_kind="exit", number=300)))
        self.assertIsNotNone(incidents.valid_group(group(number_kind="exit", number=-255)))
        self.assertIsNotNone(incidents.valid_group(group(number_kind="winerror", number=65535)))

    def test_an_occurrence_merges_and_the_51st_group_pushes_out_the_oldest(self):
        g = incidents.add({}, item())
        g = incidents.add(g, item())
        self.assertEqual(g["store.lock/lock"]["count"], 2)
        self.assertEqual(incidents.seen(2), "2")
        self.assertEqual(incidents.seen(3), "3+")
        self.assertEqual(incidents.seen(10), "10+")
        pairs = [(c, cause) for c in sorted(incidents.CODES) for cause in incidents.CAUSES][:incidents.MAX_GROUPS + 1]
        self.assertEqual(len(pairs), 51, "the premise: 51 distinct groups")
        old_day = time.strftime("%Y-%m-%d", time.localtime(time.time() - 5 * 86400))
        groups = incidents.add({}, item(code=pairs[0][0], cause=pairs[0][1]), old_day)
        for c, cause in pairs[1:]:
            groups = incidents.add(groups, item(code=c, cause=cause))
        self.assertEqual(len(groups), incidents.MAX_GROUPS)
        self.assertNotIn(f"{pairs[0][0]}/{pairs[0][1]}", groups, "the oldest group went")
        self.assertIn(f"{pairs[-1][0]}/{pairs[-1][1]}", groups)

    def test_an_item_outside_the_schema_changes_nothing(self):
        self.assertEqual(incidents.add({}, item(code="store.lock /Users/x")), {})


class RecordFileTests(_Home):
    def test_a_missing_record_is_empty_and_not_damaged(self):
        self.assertEqual(incidents.load(), ({}, False))

    def test_a_record_round_trips(self):
        groups = incidents.add({}, item())
        incidents.record_path().write_text(incidents.dumps(groups))
        self.assertEqual(incidents.load()[0], groups)

    def test_damaged_forms_are_damaged_and_never_wait(self):
        p = incidents.record_path()
        cases = {"text": b"{", "big": b" " * (incidents.MAX_BYTES + 1), "nan": b'{"version": 1, "groups": NaN}',
                 "shape": b"[]", "deep": b"[" * 100000}
        for name, data in cases.items():
            with self.subTest(name):
                p.write_bytes(data)
                self.assertTrue(incidents.load()[1])
        p.unlink()
        if hasattr(os, "mkfifo"):
            os.mkfifo(p)
            started = time.monotonic()
            self.assertTrue(incidents.load()[1])
            self.assertLess(time.monotonic() - started, 1)
            p.unlink()
        if os.name != "nt":
            target = self.home / "elsewhere.json"
            target.write_text(incidents.dumps(incidents.add({}, item())))
            p.symlink_to(target)
            self.assertEqual(incidents.load(), ({}, True))

    def test_flush_writes_the_queue_and_sets_a_damaged_record_aside(self):
        incidents.record_path().write_text("{")
        incidents.queue("store.lock", "lock", "fail-closed", "UserPromptSubmit", client="claude")
        incidents.flush()
        self.assertIn("store.lock/lock", incidents.load()[0])
        self.assertTrue((self.home / "incidents.json.corrupt").exists())

    def test_flush_skips_when_the_lock_is_busy_and_never_raises(self):
        incidents.queue("store.lock", "lock", "fail-closed", "UserPromptSubmit")
        with incidents._OneTry(self.home / incidents.LOCK_NAME) as locked:
            self.assertTrue(locked)
            incidents.flush()
        self.assertFalse(incidents.record_path().exists())
        with mock.patch.object(incidents, "load", side_effect=RuntimeError("boom")):
            incidents.queue("store.lock", "lock", "fail-closed", "UserPromptSubmit")
            incidents.flush()

    def test_no_record_without_a_home(self):
        shutil.rmtree(self.home)
        incidents.queue("store.lock", "lock", "fail-closed", "UserPromptSubmit")
        incidents.flush()
        self.assertFalse(self.home.exists())


class MarkerTests(_Home):
    def marker(self, code: str) -> Path:
        return self.home / (incidents.MARKER_PREFIX + code)

    def test_a_marker_is_folded_once_and_removed(self):
        incidents.write_marker("guard.fired")
        self.assertTrue(self.marker("guard.fired").is_dir())
        incidents.flush()
        self.assertFalse(self.marker("guard.fired").exists())
        self.assertEqual(incidents.load()[0]["guard.fired/missing"]["count"], 1)
        incidents.flush()
        self.assertEqual(incidents.load()[0]["guard.fired/missing"]["count"], 1)

    def test_only_marker_codes_and_only_into_an_existing_home(self):
        incidents.write_marker("store.lock")                    # not a marker code
        self.assertFalse(self.marker("store.lock").exists())
        shutil.rmtree(self.home)
        incidents.write_marker("guard.fired")
        self.assertFalse(self.home.exists())

    @unittest.skipIf(os.name == "nt", "symlinks need privileges on Windows")
    def test_a_symlink_at_a_marker_name_is_not_followed_not_counted_and_left_alone(self):
        victim = Path(tempfile.mkdtemp(prefix="maisecrets-victim-"))
        self.addCleanup(lambda: shutil.rmtree(victim, ignore_errors=True))
        (victim / "keep.txt").write_text("keep")
        self.marker("guard.fired").symlink_to(victim)
        incidents.write_marker("guard.fired")
        incidents.flush()
        self.assertTrue(self.marker("guard.fired").is_symlink())
        self.assertEqual(sorted(os.listdir(victim)), ["keep.txt"])
        self.assertEqual(incidents.load()[0], {})

    @unittest.skipIf(os.name == "nt", "symlinks need privileges on Windows")
    def test_a_symlinked_home_gets_no_marker_and_no_record(self):
        real = Path(tempfile.mkdtemp(prefix="maisecrets-real-"))
        self.addCleanup(lambda: shutil.rmtree(real, ignore_errors=True))
        link = Path(tempfile.mkdtemp(prefix="maisecrets-link-")) / "home"
        link.symlink_to(real)
        with mock.patch.dict(os.environ, {"MAISECRETS_HOME": str(link)}):
            incidents.write_marker("guard.fired")
            incidents.queue("store.lock", "lock", "fail-closed", "UserPromptSubmit")
            incidents.flush()
        self.assertEqual(os.listdir(real), [])

    def test_a_file_or_a_full_folder_at_a_marker_name_is_left_alone(self):
        self.marker("guard.fired").write_text("x")
        full = self.marker("launcher.import")
        full.mkdir()
        (full / "inner").write_text("x")
        incidents.flush()
        self.assertTrue(self.marker("guard.fired").is_file())
        # the full folder is claimed by the rename, its rmdir fails, and it stays with its content; not counted
        self.assertEqual([p.read_text() for p in self.home.rglob("inner")], ["x"])
        self.assertEqual(incidents.load()[0], {})
        incidents.flush()
        self.assertEqual([p.read_text() for p in self.home.rglob("inner")], ["x"])
        self.assertEqual(incidents.load()[0], {})

    def test_a_claimed_leftover_is_removed_and_not_counted(self):
        left = self.home / (incidents.MARKER_PREFIX + "guard.fired.claimed-12-345")
        left.mkdir()
        incidents.flush()
        self.assertFalse(left.exists())
        self.assertEqual(incidents.load()[0], {})

    def test_the_marker_run_cmd_leaves_in_its_launcher_folder_is_listed_folded_once_and_cleared(self):
        plugin = self.home / "localappdata" / incidents.LAUNCHER_DIR / (incidents.MARKER_PREFIX + "launcher.no-python")
        plugin.parent.mkdir(parents=True)
        with mock.patch.dict(os.environ, {"LOCALAPPDATA": str(self.home / "localappdata")}):
            plugin.mkdir()
            self.assertEqual(incidents.unfolded_markers(), ["launcher.no-python"])
            incidents.flush()
            self.assertFalse(plugin.exists())
            self.assertEqual(incidents.load()[0]["launcher.no-python/missing"]["count"], 1)
            incidents.flush()
            self.assertEqual(incidents.load()[0]["launcher.no-python/missing"]["count"], 1)
            plugin.mkdir()
            (plugin / "x").write_text("x")
            incidents.flush()
            self.assertTrue((plugin / "x").exists(), "a full folder stays and counts for nothing")
            self.assertEqual(incidents.load()[0]["launcher.no-python/missing"]["count"], 1)
            (plugin / "x").unlink()
            self.assertEqual(incidents.clear(), 2)
            self.assertFalse(plugin.exists())

    def test_a_failed_rmdir_counts_nothing(self):
        incidents.write_marker("guard.fired")
        with mock.patch.object(incidents.os, "rmdir", side_effect=OSError(39, "not empty")):
            incidents.flush()
        self.assertNotIn("guard.fired/missing", incidents.load()[0])

    def test_the_pending_prompts_and_other_names_are_never_touched(self):
        pending = self.home / "pending"
        pending.mkdir()
        (pending / "S1.txt").write_text("a blocked prompt")
        other = self.home / (incidents.MARKER_PREFIX + "not-a-code")
        other.mkdir()
        incidents.flush()
        self.assertTrue((pending / "S1.txt").exists())
        self.assertTrue(other.exists())

    def test_clear_removes_record_aside_lock_temp_and_markers_and_nothing_else(self):
        for n in ("incidents.json", "incidents.json.corrupt", "incidents.json.77.tmp", "index.json"):
            (self.home / n).write_text("x")
        incidents.write_marker("guard.fired")
        self.assertEqual(incidents.clear(), 4)
        self.assertEqual(sorted(os.listdir(self.home)), [incidents.LOCK_NAME, "index.json"],
                         "the lock stays: a second hook must not lock a new file while the first holds the old one")

    def test_clear_waits_for_no_busy_lock_and_removes_nothing_then(self):
        incidents.record_path().write_text("x")
        with incidents._OneTry(self.home / incidents.LOCK_NAME):
            self.assertEqual(incidents.clear(), -1)
        self.assertTrue(incidents.record_path().exists())


class FormTests(unittest.TestCase):
    # the six forms Claude Code expands to maisecrets:report that a plain prefix missed (Opus, round 5, measured)
    EXPANDED = ["/maisecrets:report\tincident", "/maisecrets:report  incident", "/maisecrets:report\nincident",
                '/maisecrets:report "incident"', "/maisecrets:report Incident", "/maisecrets:report --create incident"]

    def test_the_expanded_forms_are_all_incident_reports(self):
        for prompt in self.EXPANDED:
            with self.subTest(prompt):
                self.assertEqual(incidents.recognize(prompt, "claude"), ("show", None))

    def test_the_cli_and_the_hook_agree(self):
        for prompt in self.EXPANDED + ["/maisecrets:report incident store.lock/lock",
                                       "/maisecrets:report incident please", "/maisecrets:report incident clear",
                                       "/maisecrets:report last", "/maisecrets:report bug it broke"]:
            with self.subTest(prompt):
                rest = prompt[len("/maisecrets:report"):]
                self.assertEqual(incidents.recognize(prompt, "claude"), incidents.form(incidents.words_of(rest)))

    def test_forms_the_client_does_not_expand_and_other_reports_are_no_match(self):
        for prompt in [" /maisecrets:report incident", "/MAISECRETS:report incident", "/report incident",
                       "/maisecrets:report incidentally", "/maisecrets:report last", "/maisecrets:reporting incident",
                       "/maisecrets:report", "/maisecrets:report bug incident"]:
            with self.subTest(prompt):
                self.assertIsNone(incidents.recognize(prompt, "claude"))

    def test_codex_and_odd_payloads_are_no_match(self):
        self.assertIsNone(incidents.recognize("/maisecrets:report incident", "codex"))
        self.assertIsNone(incidents.recognize(None, "claude"))

    def test_near_misses_get_the_usage_line(self):
        for words in (["incident", "please"], ["incident", "store.lock/locked"], ["incident", "a", "b"],
                      ["incident", "x/lock"]):
            with self.subTest(words):
                self.assertEqual(incidents.form(words), ("usage", None))
        self.assertEqual(incidents.form(["incident", "Store.Lock/Lock"]), ("show", "store.lock/lock"))
        self.assertEqual(incidents.form(["incident", "clear"]), ("clear", None))


class ReportTests(_Home):
    def setUp(self):
        super().setUp()
        (self.home / "config.json").write_text('{"backend": "jsonfile", "allow_plaintext_store": true}')

    def test_every_code_renders_without_a_detector_hit_and_with_a_short_link(self):
        from maisecrets import detect
        for code in sorted(incidents.CODES):
            for cause in incidents.CAUSES:
                with self.subTest(code=code, cause=cause):
                    g = incidents.valid_group(group(code=code, cause=cause, number_kind="winerror", number=65535,
                                                    days=[TODAY], count=9999, plugin_version="999.999.999"))
                    title, body = incidents.issue(g)
                    self.assertEqual(detect.scan(title + "\n" + body), [])
                    text = incidents.render({incidents._key(g): g}, None)
                    link = [x for x in text.splitlines() if x.startswith("link: ")][0]
                    self.assertTrue(link.startswith("link: https://github.com/"), link)
                    self.assertLessEqual(len(link) - 6, incidents.URL_LIMIT)

    def test_a_broken_config_gives_the_text_without_a_link_and_without_error_text(self):
        from maisecrets import events
        from maisecrets.vault import ConfigError
        groups = incidents.add({}, item())
        private = str(self.home / "policy-at-a-private-path.json")
        with mock.patch.object(events, "tracker", side_effect=ConfigError(f"{private} is not valid JSON")):
            text = incidents.render(groups, None)
        self.assertIn("link: unavailable (configuration)", text)
        self.assertNotIn(str(self.home), text)

    def test_the_report_sends_nothing_and_starts_no_program(self):
        incidents.record_path().write_text(incidents.dumps(incidents.add({}, item())))
        incidents.write_marker("guard.fired")
        import socket
        import webbrowser
        with mock.patch.object(subprocess, "Popen", side_effect=AssertionError("a program")), \
                mock.patch.object(socket, "socket", side_effect=AssertionError("a connection")), \
                mock.patch.object(webbrowser, "open", side_effect=AssertionError("a browser")):
            text = incidents.report_text()
        self.assertIn("store.lock/lock", text)
        self.assertIn("Not yet counted: guard.fired", text)
        self.assertTrue(self.marker_still_there())

    def marker_still_there(self) -> bool:
        return (self.home / (incidents.MARKER_PREFIX + "guard.fired")).is_dir()

    def test_a_selector_picks_its_group(self):
        groups = incidents.add(incidents.add({}, item()), item(code="store.openssl", cause="rc"))
        self.assertIn("Report for store.openssl/rc", incidents.render(groups, "store.openssl/rc"))

    def test_an_empty_record_says_so(self):
        self.assertIn("No internal failure", incidents.report_text())


if __name__ == "__main__":
    unittest.main()
