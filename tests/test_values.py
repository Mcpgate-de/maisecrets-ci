"""Values from your own tools (maisecrets/values.py, C26, #19 part 3): the import, the floor, the caps, the file
checks, the imports pass of the registry, mask only, provenance, and the rule that only the person removes an import.

A placeholder here is built from OPEN and CLOSE, so the file holds none. Invented names and values only.

Run: python3 -m unittest tests.test_values -v
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import re
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

from maisecrets import cli, detect, hooks, incidents, registry, value_files, values  # noqa: E402
from maisecrets.placeholder import CLOSE, OPEN  # noqa: E402
from maisecrets.vault import HOME, Vault, load_config  # noqa: E402
import _hygiene  # noqa: E402
from _hygiene import CLAUDE, CODEX  # noqa: E402

NAME = "Zbigniew " + "Testowski"
CODE = "Quarzel-" + "Wendrop-55"           # a value without a shape, as a tool of the person finds it
STATE = ("index.json", "vault.json", "audit.log", "hooks.log", "events.log", ".values-state", ".values-cache",
         ".values.lock")
REF_RE = re.compile(re.escape(OPEN) + r"([A-Z]+_c\d+)" + re.escape(CLOSE))
SETTINGS_ADD = "/maisecrets:" + "settings value_files add"


def _clean() -> None:
    for f in STATE:
        try:
            os.unlink(Path(HOME, f))
        except FileNotFoundError:
            pass
    if values.IMPORTS.is_dir():
        for p in values.IMPORTS.iterdir():
            p.unlink()
        values.IMPORTS.rmdir()
    Path(HOME, "config.json").write_text('{"backend": "jsonfile", "allow_plaintext_store": true}')
    incidents.clear(Path(HOME))
    hooks._live_cache.clear()
    detect.reset_rules()


def setUpModule():  # noqa: N802 - unittest hook
    _clean()


def tearDownModule():  # noqa: N802 - unittest hook
    _clean()
    _hygiene.assert_pristine()


class _Files(unittest.TestCase):
    def setUp(self):
        _clean()
        self.dir = Path(tempfile.mkdtemp(prefix="ms-values-src-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(self.dir, ignore_errors=True))
        self.addCleanup(_clean)

    def file(self, rows, name="ner.jsonl", raw: str | None = None) -> Path:
        p = self.dir / name
        text = raw if raw is not None else "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows)
        p.write_text(text, encoding="utf-8")
        os.chmod(p, 0o600)
        return p

    def imported(self, rows, name="ner.jsonl", origin="run") -> values.Result:
        r = values.import_file(self.file(rows, name), origin)
        detect.reset_rules()
        return r


def _bash(stdout: str, session: str = "S1") -> dict:
    hooks._live_cache.clear()
    return hooks.post_tool({"hook_event_name": "PostToolUse", "tool_name": "Bash", "session_id": session,
                            "tool_input": {"command": "cat notes.txt"}, **CLAUDE,
                            "tool_response": {"stdout": stdout, "stderr": ""}})


def _out(answer: dict) -> str:
    return answer["hookSpecificOutput"]["updatedToolOutput"]["stdout"]


def _kinds() -> dict:
    return {k: m.get("kind") for k, m in json.loads(Path(HOME, "index.json").read_text())["entries"].items()}


# --------------------------------------------------------------------------------------------- the floor --
class Floor(unittest.TestCase):
    def test_a_value_that_is_short_common_or_of_maisecrets_itself_is_refused(self):
        rows = [{"value": v} for v in ("Abc", "return", "the end", "2024", "ab\x01cdef", "Mein maisecrets Wert",
                                       "import:v12345678", OPEN + "x" + CLOSE)]
        text = "".join(json.dumps(r) + "\n" for r in rows)
        items, refused, _dups = values.parse(text)
        self.assertEqual(items, [])
        self.assertEqual([n for n, _w in refused], list(range(1, len(rows) + 1)))

    def test_a_name_an_address_and_a_long_number_pass(self):
        text = "".join(json.dumps(r) + "\n" for r in (
            {"value": NAME, "type": "NAME"}, {"value": "Kowalsky", "type": "name"},
            {"value": "z.testowski" + "@" + "example.org", "type": "EMAIL"}, {"value": "4711203", "type": "PHONE"}))
        items, refused, _dups = values.parse(text)
        self.assertEqual(refused, [])
        self.assertEqual([t for _v, t, _n in items], ["NAME", "NAME", "EMAIL", "PHONE"])

    def test_a_refusal_never_holds_the_value_or_the_type_text(self):
        text = json.dumps({"value": "Wurzelbert Pomm", "type": "Wurzelbert Pomm"}) + "\n"
        _items, refused, _dups = values.parse(text)
        self.assertNotIn("Wurzelbert", repr(refused))

    def test_no_field_of_a_line_can_loosen_anything(self):
        # only value and type are read: a field that names a rule, an allow list or a lifetime is ignored
        text = json.dumps({"value": NAME, "type": "NAME", "allow": True, "rule": "email", "ttl": 0,
                           "remove": "v12345678"}) + "\n"
        items, refused, _dups = values.parse(text)
        self.assertEqual(([(v, t) for v, t, _n in items], refused), ([(NAME, "NAME")], []))


# ---------------------------------------------------------------------------------------- the import --
class Import(_Files):
    def test_an_imported_name_is_masked_as_a_phrase_in_any_spacing_and_case(self):
        r = self.imported([{"value": NAME, "type": "NAME"}])
        hits = detect.scan("Mail von zbigniew \n  TESTOWSKI heute", channel="tool")
        self.assertEqual([(m.kind, m.type) for m in hits], [(f"import:{r.id}:{hits[0].kind.rsplit(':', 1)[1]}",
                                                             "NAME")])
        self.assertEqual(value_files.import_of(hits[0].kind), r.id)

    def test_a_new_import_of_the_same_file_only_adds(self):
        p = self.file([{"value": NAME, "type": "NAME"}, {"value": CODE}])
        first = values.import_file(p)
        p.write_text(json.dumps({"value": "Wendelin Quapp", "type": "NAME"}) + "\n")
        second = values.import_file(p)
        detect.reset_rules()
        self.assertEqual(second.id, first.id)
        self.assertTrue(second.merged)
        text = f"{NAME}, {CODE} und Wendelin Quapp"
        self.assertEqual(len(detect.scan(text, channel="tool")), 3, "a value the file no longer lists stays")

    def test_the_summary_names_the_import_by_id_never_by_file_or_value(self):
        p = self.file([{"value": NAME, "type": "NAME"}], name=NAME.replace(" ", "_") + ".jsonl")
        r = values.import_file(p)
        said = values.summary(r)
        self.assertRegex(said, r"import:v[0-9a-f]{8}")
        for piece in ("Zbigniew", "Testowski", p.name):
            self.assertNotIn(piece, said)

    def test_an_import_writes_an_events_line_with_its_id_and_counts_only(self):
        r = self.imported([{"value": NAME, "type": "NAME"}])
        log = Path(HOME, "events.log").read_text()
        self.assertIn(f"import:{r.id}", log)
        self.assertNotIn("Testowski", log)

    def test_the_import_file_is_private(self):
        r = self.imported([{"value": NAME, "type": "NAME"}])
        if os.name != "nt":
            self.assertEqual(os.stat(values.IMPORTS / f"{r.id}.jsonl").st_mode & 0o077, 0)
            self.assertEqual(os.stat(values.IMPORTS).st_mode & 0o077, 0)


class Caps(_Files):
    def test_a_flood_stops_at_the_cap_of_one_import_with_a_message(self):
        with mock.patch.object(values, "MAX_PER_IMPORT", 3):
            r = self.imported([{"value": f"Wertname Nummer{i:03d}", "type": "NAME"} for i in range(10)])
        self.assertEqual(r.added, 3)
        self.assertIn("line 4 and later not imported", r.stopped)
        self.assertIn("/maisecrets:forget import:ID", r.stopped)

    def test_the_cap_of_all_imports_holds(self):
        with mock.patch.object(values, "MAX_VALUES", 4):
            self.imported([{"value": f"Erstname Nummer{i:03d}"} for i in range(3)], name="a.jsonl")
            r = self.imported([{"value": f"Zweitname Nummer{i:03d}"} for i in range(3)], name="b.jsonl")
        self.assertEqual(r.added, 1)
        self.assertIn("imported values, the limit", r.stopped)

    def test_the_imports_of_commands_leave_room_for_the_value_files(self):
        Path(HOME, "config.json").write_text(json.dumps({"backend": "jsonfile", "allow_plaintext_store": True,
                                                         "value_files": [str(self.dir / "file.jsonl")]}))
        with mock.patch.object(values, "MAX_RUN_VALUES", 2), mock.patch.object(values, "MAX_VALUES", 10):
            r = self.imported([{"value": f"Laufname Nummer{i:03d}"} for i in range(5)], name="run.jsonl")
            f = self.imported([{"value": f"Dateiname Nummer{i:03d}"} for i in range(5)], name="file.jsonl",
                              origin="file")
        self.assertEqual((r.added, f.added), (2, 5))

    def test_the_number_of_imports_is_capped(self):
        with mock.patch.object(values, "MAX_IMPORTS", 2):
            self.imported([{"value": "Erstname Eins"}], name="1.jsonl")
            self.imported([{"value": "Zweitname Zwei"}], name="2.jsonl")
            with self.assertRaisesRegex(ValueError, "2 imports, the limit"):
                self.imported([{"value": "Drittname Drei"}], name="3.jsonl")


class FileChecks(_Files):
    def test_a_symbolic_link_is_refused(self):
        target = self.file([{"value": NAME}])
        link = self.dir / "link.jsonl"
        os.symlink(target, link)
        with self.assertRaisesRegex(ValueError, "symbolic link"):
            values.import_file(link)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "no FIFO on this system")
    def test_a_fifo_is_refused_without_waiting_for_a_writer(self):
        fifo = self.dir / "pipe.jsonl"
        os.mkfifo(fifo)
        t = time.monotonic()
        with self.assertRaisesRegex(ValueError, "not a regular file"):
            values.import_file(fifo)
        self.assertLess(time.monotonic() - t, 2)

    def test_a_file_over_the_bound_is_refused_and_read_only_to_the_bound(self):
        p = self.file([{"value": f"Wertname Nummer{i:03d}"} for i in range(50)])
        reads = []
        real = os.read

        def counting(fd, n):
            data = real(fd, n)
            reads.append(len(data))
            return data
        with mock.patch.object(values, "MAX_FILE_BYTES", 100), mock.patch.object(values.os, "read", counting):
            with self.assertRaisesRegex(ValueError, "larger than"):
                values.import_file(p)
        self.assertLessEqual(sum(reads), 101, "a growing file is read once, up to the bound")

    @unittest.skipIf(os.name == "nt", "POSIX owners and modes")
    def test_a_file_every_user_can_write_is_refused(self):
        p = self.file([{"value": NAME}])
        os.chmod(p, 0o666)
        with self.assertRaisesRegex(ValueError, "every user can write it"):
            values.import_file(p)

    @unittest.skipIf(os.name == "nt", "POSIX owners and modes")
    def test_a_file_of_another_user_is_refused(self):
        p = self.file([{"value": NAME}])
        real = os.fstat

        def other(fd):
            st = real(fd)
            return os.stat_result((st.st_mode, st.st_ino, st.st_dev, st.st_nlink, os.getuid() + 4242, st.st_gid,
                                   st.st_size, st.st_atime, st.st_mtime, st.st_ctime))
        with mock.patch.object(values.os, "fstat", other):
            with self.assertRaisesRegex(ValueError, "owned by another user"):
                values.import_file(p)

    def test_a_line_a_writer_has_not_finished_is_refused_and_the_rest_imports(self):
        raw = json.dumps({"value": NAME, "type": "NAME"}) + "\n" + '{"value": "Wendelin Qu'
        r = values.import_file(self.file([], raw=raw))
        self.assertEqual((r.added, [n for n, _w in r.refused]), (1, [2]))

    def test_the_checks_run_on_the_opened_file_not_on_the_path(self):
        # a file swapped between a check and the read (TOCTOU): there is no check before the open, and the open
        # does not follow a link, so a link swapped in fails at the open itself
        p = self.file([{"value": NAME}])
        calls = []
        real_open = os.open

        def spy(path, flags, *a):
            calls.append(flags)
            return real_open(path, flags, *a)
        with mock.patch.object(values.os, "open", spy), mock.patch.object(values.os, "stat",
                                                                          side_effect=AssertionError("a path check")):
            values.read_source(p)
        self.assertTrue(calls and calls[0] & getattr(os, "O_NOFOLLOW", 0) == getattr(os, "O_NOFOLLOW", 0))
        self.assertTrue(calls[0] & getattr(os, "O_NONBLOCK", 0) == getattr(os, "O_NONBLOCK", 0))


# ------------------------------------------------------------------------------------- the registry --
class Registry(_Files):
    def test_the_imports_pass_is_a_class_of_its_own(self):
        spec = [s for s in detect.pass_specs() if s.source == "imports"]
        self.assertEqual([(s.key, s.origin, s.rule_class, s.matcher) for s in spec],
                         [("imports:import", "import", "import", "import")])
        self.assertEqual(spec[0].priority[0], registry.PHASES["imports"])
        self.assertGreater(registry.PHASES["imports"], registry.PHASES["terms"])

    def test_enabled_turns_the_pass_on_and_off(self):
        self.imported([{"value": NAME, "type": "NAME"}])
        text = f"an {NAME}"
        self.assertEqual(len(detect.scan(text, enabled={"imports:import"})), 1)
        self.assertEqual(detect.scan(text, enabled={"email"}), [])

    def test_without_an_import_the_values_module_is_not_loaded(self):
        code = ("import sys; sys.path.insert(0, %r); from maisecrets import detect; "
                "detect.scan('Mail an Zbigniew Testowski und mehr Text'); "
                "print('maisecrets.values' in sys.modules, 'maisecrets.terms' in sys.modules)" % str(ROOT))
        out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=60,
                             env=dict(os.environ))
        self.assertEqual(out.stdout.split(), ["False", "False"], out.stderr)

    def test_an_imported_value_inside_a_rule_hit_keeps_the_rules_kind(self):
        # an import only adds: an email address that the email rule finds keeps its kind and stays resolvable
        address = "z.testowski" + "@" + "firma-xyz.de"
        self.imported([{"value": address, "type": "EMAIL"}, {"value": NAME, "type": "NAME"}])
        hits = detect.scan(f"{NAME} wrote; reply to {address}", channel="tool")
        self.assertEqual(sorted(m.kind.split(":")[0] for m in hits), ["email", "import"])


# ------------------------------------------------------------------------------- through the hooks --
class Hooks(_Files):
    def test_a_tool_result_is_masked_and_the_store_never_holds_the_value(self):
        r = self.imported([{"value": NAME, "type": "NAME"}])
        out = _out(_bash(f"the file of {NAME} is ready"))
        self.assertNotIn("Testowski", out)
        key = REF_RE.search(out).group(1)
        self.assertEqual(value_files.import_of(_kinds()[key]), r.id)
        self.assertNotIn(b"Testowski", Path(HOME, "vault.json").read_bytes())

    def test_a_typed_prompt_with_an_imported_value_is_stopped(self):
        self.imported([{"value": NAME, "type": "NAME"}])
        hooks._live_cache.clear()
        _hygiene.patch(self, hooks, "_clipboard", lambda t: True)
        ans = hooks.user_prompt({"prompt": f"Write to {NAME} today", "session_id": "S1", **CLAUDE})
        self.assertEqual(ans.get("decision"), "block")

    def test_an_import_placeholder_is_never_put_into_a_command(self):
        self.imported([{"value": NAME, "type": "NAME"}])
        ref = REF_RE.search(_out(_bash(f"the file of {NAME} is ready"))).group()
        for tool, tool_input in (("Bash", {"command": f"echo 'Dear {ref}' > letter.txt"}),
                                 ("Write", {"file_path": "/tmp/letter.txt", "content": f"Dear {ref},\n"}),
                                 ("mcp__mail__draft", {"to": "x", "body": f"Dear {ref}"})):
            with self.subTest(tool=tool):
                out = hooks.pre_tool({"hook_event_name": "PreToolUse", "tool_name": tool, "session_id": "S1",
                                      "transcript_path": "", **CLAUDE, "tool_input": tool_input, "cwd": "/tmp"})
                self.assertNotEqual(out.get("hookSpecificOutput", {}).get("permissionDecision"), "deny", out)
                self.assertNotIn("Testowski", json.dumps(out))
                self.assertNotIn(value_files.STORE_PREFIX, json.dumps(out))
                updated = out.get("hookSpecificOutput", {}).get("updatedInput")
                if updated is not None:
                    self.assertEqual(updated, tool_input)

    def test_a_stored_resolvable_value_keeps_its_placeholder_and_its_entry(self):
        # an import must not change a stored value: not its type, not its kind, and it must stay resolvable
        v = Vault(load_config())
        stored = v.put(CODE, "SECRET", "manual", session="S1")
        before = json.loads(Path(HOME, "index.json").read_text())["entries"][stored.key]
        self.imported([{"value": CODE, "type": "NAME"}, {"value": NAME, "type": "NAME"}])
        out = _out(_bash(f"{CODE} for {NAME}"))
        refs = REF_RE.findall(out)
        self.assertIn(stored.key, refs)
        self.assertEqual(len(refs), 2, out)
        after = json.loads(Path(HOME, "index.json").read_text())["entries"][stored.key]
        self.assertEqual((after["type"], after["kind"]), (before["type"], before["kind"]))
        self.assertNotIn(stored.key, hooks._term_keys(), "the stored value still resolves")

    def test_a_stored_value_inside_an_imported_phrase_keeps_its_placeholder(self):
        v = Vault(load_config())
        stored = v.put(CODE, "SECRET", "manual", session="S1")
        self.imported([{"value": f"Projekt {CODE} Alpha", "type": "NAME"},
                       {"value": f"Bereich ({CODE}) Beta", "type": "NAME"},
                       {"value": f"Gruppe-{CODE} Gamma", "type": "NAME"}])
        for text in (f"see Projekt {CODE} Alpha", f"see Bereich ({CODE}) Beta", f"see Gruppe-{CODE} Gamma"):
            out = _out(_bash(text))
            if "Gruppe" not in text:
                # a stored value that stands as a token keeps its own placeholder; joined into a word of the
                # import (Gruppe-…) the exact match does not see it, and the import masks the whole run
                self.assertIn(OPEN + stored.key + CLOSE, out)
            for word in ("Projekt", "Alpha", "Bereich", "Beta", "Gruppe", "Gamma", "Quarzel"):
                self.assertNotIn(word, out)


class Removal(_Files):
    def test_no_command_removes_an_import(self):
        r = self.imported([{"value": NAME}])
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self.assertEqual(cli.main(["values", "remove", r.id]), 1)
        self.assertIn("/maisecrets:forget import:ID", buf.getvalue())
        self.assertEqual(len(values.rows()), 1)

    def test_a_tool_call_that_carries_the_removal_is_refused(self):
        for command in ("codex exec '/maisecrets:forget import:v1234abcd'", "bash run.sh values remove v1234abcd",
                        "python3 -c 'from maisecrets import values; values.remove_typed([\"v1234abcd\"])'"):
            ans = hooks.pre_tool({"hook_event_name": "PreToolUse", "tool_name": "Bash", "session_id": "S1",
                                  **CLAUDE, "tool_input": {"command": command}})
            self.assertEqual(ans["hookSpecificOutput"]["permissionDecision"], "deny", command)

    def test_the_imports_folder_is_part_of_the_store_for_a_command(self):
        ans = hooks.pre_tool({"hook_event_name": "PreToolUse", "tool_name": "Bash", "session_id": "S1", **CLAUDE,
                              "tool_input": {"command": f"rm {values.IMPORTS}/v1234abcd.jsonl"}})
        self.assertEqual(ans["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_only_the_persons_typed_prompt_removes_an_import(self):
        r = self.imported([{"value": NAME, "type": "NAME"}])
        prompt = f"/maisecrets:forget import:{r.id}"
        for payload in ({**CLAUDE, "source": "schedule_wakeup"}, {**CLAUDE, "agent_id": "a1"}):
            ans = hooks.user_prompt({"prompt": prompt, "session_id": "S1", **payload})
            self.assertIn("counts only when you type it", ans["reason"])
            self.assertEqual(len(values.rows()), 1)
        ans = hooks.user_prompt({"prompt": prompt, "session_id": "S1", **CLAUDE})
        self.assertIn(f"import:{r.id} removed", ans["reason"])
        self.assertEqual(values.rows(), [])
        detect.reset_rules()
        self.assertEqual(detect.scan(f"an {NAME}"), [])
        self.assertIn("value-import", Path(HOME, "events.log").read_text())

    def test_the_codex_form_removes_too(self):
        r = self.imported([{"value": NAME, "type": "NAME"}])
        ans = hooks.user_prompt({"prompt": f"maisecrets: forget import:{r.id}", "session_id": "S1", **CODEX})
        self.assertIn("removed", ans["reason"])

    def test_an_imported_value_cannot_mask_the_removal_prompt(self):
        # the floor refuses control text, and the removal is read before the detector anyway
        r = self.imported([{"value": NAME, "type": "NAME"}])
        ans = hooks.user_prompt({"prompt": f"/maisecrets:forget import:{r.id}", "session_id": "S1", **CLAUDE})
        self.assertNotIn(OPEN, ans["reason"])
        self.assertIn("removed", ans["reason"])


class ReviewRoundOne(_Files):
    """The findings of Gate A (codex gpt-5.6-sol) and Gate B (Opus) on the first build, each with a test."""

    def _config(self, files: list) -> dict:
        cfg = {"backend": "jsonfile", "allow_plaintext_store": True, "value_files": [str(f) for f in files]}
        Path(HOME, "config.json").write_text(json.dumps(cfg))
        return load_config()

    def test_imports_of_commands_leave_places_for_the_value_files(self):
        with mock.patch.object(values, "MAX_RUN_IMPORTS", 2), mock.patch.object(values, "MAX_IMPORTS", 3):
            self.imported([{"value": "Erstname Eins"}], name="1.jsonl")
            self.imported([{"value": "Zweitname Zwei"}], name="2.jsonl")
            with self.assertRaisesRegex(ValueError, "imports of commands, their limit"):
                self.imported([{"value": "Drittname Drei"}], name="3.jsonl")
            p = self.file([{"value": NAME, "type": "NAME"}], name="mine.jsonl")
            values.session_note(self._config([p]))
        detect.reset_rules()
        self.assertEqual(len(detect.scan(f"an {NAME}")), 1)

    def test_a_command_import_of_a_value_file_is_an_import_of_its_own(self):
        p = self.file([{"value": NAME, "type": "NAME"}], name="mine.jsonl")
        values.session_note(self._config([p]))
        values.import_file(p)
        self.assertEqual(sorted(r["origin"] for r in values.rows()), ["file", "run"])

    def test_a_value_two_imports_list_stays_when_one_is_removed(self):
        a = self.imported([{"value": NAME, "type": "NAME"}], name="a.jsonl")
        b = self.imported([{"value": NAME, "type": "NAME"}, {"value": CODE}], name="b.jsonl")
        self.assertEqual((b.added, b.known), (2, 0))
        values.remove_typed([a.id])
        detect.reset_rules()
        self.assertEqual(len(detect.scan(f"an {NAME}")), 1)

    def test_a_value_file_whose_import_is_gone_is_imported_again(self):
        p = self.file([{"value": NAME, "type": "NAME"}], name="mine.jsonl")
        cfg = self._config([p])
        values.session_note(cfg)
        values.remove_typed([values.rows()[0]["id"]])
        values.session_note(cfg)
        detect.reset_rules()
        self.assertEqual(len(detect.scan(f"an {NAME}")), 1)

    def test_a_setting_key_or_a_placeholder_key_is_no_value(self):
        text = "".join(json.dumps({"value": v}) + "\n" for v in ("value_files", "Mein rule_dirs Ordner",
                                                                  "PASSWORD_c1", "secret_c12 alt"))
        items, refused, _d = values.parse(text)
        self.assertEqual((items, [n for n, _w in refused]), ([], [1, 2, 3, 4]))

    def test_an_import_hit_never_lands_inside_a_placeholder(self):
        with mock.patch.object(values, "_reason", lambda v: ""):
            self.imported([{"value": "SECRET_c1"}])
        hits = detect.scan(f"use {OPEN}SECRET_c1{CLOSE} now", channel="tool")
        self.assertFalse([m for m in hits if m.kind.startswith("import:")])

    def test_the_mod_leaves_a_settings_prompt_to_the_hook(self):
        self.imported([{"value": "Kroneberg Pfadwert", "type": "NAME"}])
        prompt = SETTINGS_ADD + " /home/x/Kroneberg Pfadwert/v.jsonl"
        self.assertEqual(hooks.rewrite_prompt({"prompt": prompt, "session_id": "S1", "cwd": ""}), {})

    def test_a_file_in_the_imports_folder_that_is_no_import_fails_closed(self):
        r = self.imported([{"value": NAME, "type": "NAME"}])
        os.rename(values.IMPORTS / f"{r.id}.jsonl", values.IMPORTS / "broken.jsonl")
        detect.reset_rules()
        with self.assertRaises(values.ValuesError):
            detect.scan(f"an {NAME}")

    def test_a_damaged_import_withholds_a_tool_result(self):
        r = self.imported([{"value": NAME, "type": "NAME"}])
        (values.IMPORTS / f"{r.id}.jsonl").write_text("not json\n")
        detect.reset_rules()
        hooks._live_cache.clear()
        out = hooks._post_tool_guarded({"hook_event_name": "PostToolUse", "tool_name": "Bash", "session_id": "S1",
                                        "tool_input": {"command": "cat notes.txt"}, **CLAUDE,
                                        "tool_response": {"stdout": f"an {NAME}", "stderr": ""}})
        self.assertIn(f"import:{r.id} is damaged", json.dumps(out))
        self.assertNotIn("Testowski", json.dumps(out))

    def test_a_flood_of_lines_is_read_to_a_bound_and_the_refusals_are_counted(self):
        with mock.patch.object(values, "MAX_LINES", 50):
            r = values.import_file(self.file([], raw="0\n" * 200))
        self.assertLessEqual(len(r.refused), values.MAX_REFUSED_SHOWN)
        self.assertEqual(r.refused_count, 51)
        self.assertIn("51 line(s) refused", values.summary(r))

    def test_a_removal_split_over_two_lines_in_a_command_is_refused(self):
        command = "codex exec 'maisecrets: forget\n import:v1234abcd'"
        ans = hooks.pre_tool({"hook_event_name": "PreToolUse", "tool_name": "Bash", "session_id": "S1", **CLAUDE,
                              "tool_input": {"command": command}})
        self.assertEqual(ans["hookSpecificOutput"]["permissionDecision"], "deny")


class ReviewRoundTwo(_Files):
    """The findings of round 2 of Gate A (codex gpt-5.6-sol) and Gate B (Opus), each with a test."""

    def test_an_imported_value_in_the_display_text_of_a_placeholder_is_masked(self):
        self.imported([{"value": NAME, "type": "NAME"}])
        key = "NAME_" + "c1"
        for text in (f"row: {OPEN}{key}:{NAME}{CLOSE}", f"{OPEN} row: <{key}:{NAME}>"):
            hits = detect.scan(text, channel="tool")
            self.assertTrue([m for m in hits if m.kind.startswith("import:")], text)

    def test_a_removal_padded_with_white_space_in_a_command_is_refused(self):
        command = "codex exec 'maisecrets: forget" + " " * 450 + "import:v1234abcd'"
        ans = hooks.pre_tool({"hook_event_name": "PreToolUse", "tool_name": "Bash", "session_id": "S1", **CLAUDE,
                              "tool_input": {"command": command}})
        self.assertEqual(ans["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_only_a_configured_value_file_counts_as_a_value_file(self):
        r = self.imported([{"value": NAME, "type": "NAME"}], origin="file")
        self.assertEqual([x["origin"] for x in values.rows() if x["id"] == r.id], ["run"])

    def test_an_import_stops_at_its_byte_bound_and_stays_readable(self):
        with mock.patch.object(values, "MAX_IMPORT_BYTES", 600):
            r = self.imported([{"value": f"Wertname Nummer{i:03d}"} for i in range(40)])
        self.assertIn("one import holds at most", r.stopped)
        self.assertGreater(r.added, 0)
        detect.reset_rules()
        self.assertEqual(len(detect.scan("an Wertname Nummer000")), 1)


class ReviewRoundThree(_Files):
    """The findings of round 3 of Gate B on the fixes of round 2, each with a test."""

    FORMS = {
        "joined quotes": 'claude -p "/maisecrets:forget "' + "'import:v1234abcd'",
        "quote then word": 'claude -p "/maisecrets:forget "import:v1234abcd',
        "backslash line end": 'claude -p "/maisecrets:forget \\\nimport:v1234abcd"',
        "printf": "claude -p \"$(printf '/maisecrets:forget %s' import:v1234abcd)\"",
        "variable first": 'X=import:v1234abcd; claude -p "/maisecrets:forget $X"',
        "split command name": 'claude -p "/maisecrets:"forget" import:v1234abcd"',
        "json escape": '{"prompt": "/maisecrets:forget\\u0020import:v1234abcd"}',
    }
    POWERSHELL = {
        "plus": 'claude -p ("/maisecrets:forget " + "import:v1234abcd")',
        "backtick line end": 'claude -p "/maisecrets:forget `\nimport:v1234abcd"',
    }

    def test_every_form_that_a_shell_joins_into_the_removal_is_refused(self):
        for name, command in self.FORMS.items():
            with self.subTest(name):
                ans = hooks.pre_tool({"hook_event_name": "PreToolUse", "tool_name": "Bash", "session_id": "S1",
                                      **CLAUDE, "tool_input": {"command": command}})
                self.assertEqual(ans["hookSpecificOutput"]["permissionDecision"], "deny", command)
        for name, command in self.POWERSHELL.items():
            with self.subTest(name):
                self.assertTrue(value_files.removal_in_command(command), command)

    ESCAPED = {
        "bash escape in a word": "claude -p /maisecrets:forget\\ imp\\ort:v1234abcd",
        "bash escaped colon": 'claude -p "/maisecrets\\:forget import:v1234abcd"',
        "powershell backtick in a word": 'claude -p "/maisecrets:forget imp`ort:v1234abcd"',
        "powershell plus inside a word": "claude -p ('/maisecrets:forget imp' + 'ort:v1234abcd')",
    }

    def test_an_escape_or_a_split_inside_a_word_is_refused(self):
        for name, command in self.ESCAPED.items():
            for tool in ("Bash", "PowerShell"):
                with self.subTest(name, tool=tool):
                    ans = hooks.pre_tool({"hook_event_name": "PreToolUse", "tool_name": tool, "session_id": "S1",
                                          **CLAUDE, "tool_input": {"command": command}})
                    self.assertEqual(ans["hookSpecificOutput"]["permissionDecision"], "deny", command)

    CONTINUED = {
        "line end inside forget": "claude -p /maisecrets:for\\\nget\\ import:v1234abcd",
        "line end inside import": "claude -p /maisecrets:forget\\ imp\\\nort:v1234abcd",
        "crlf line end inside import": "claude -p /maisecrets:forget\\ imp\\\r\nort:v1234abcd",
        "quoted halves over a line end": "claude -p '/maisecrets:forget imp'\\\n'ort:v1234abcd'",
        "codex over a line end": "codex exec 'maisecrets: forget imp'\\\n'ort:v1234abcd'",
        "powershell backtick line end inside a word": "claude -p /maisecrets:forget` imp`\nort:v1234abcd",
    }

    def test_a_line_end_inside_a_word_of_a_removal_is_refused(self):
        for name, command in self.CONTINUED.items():
            for tool in ("Bash", "PowerShell"):
                with self.subTest(name, tool=tool):
                    ans = hooks.pre_tool({"hook_event_name": "PreToolUse", "tool_name": tool, "session_id": "S1",
                                          **CLAUDE, "tool_input": {"command": command}})
                    self.assertEqual(ans["hookSpecificOutput"]["permissionDecision"], "deny", command)

    def test_each_round_of_the_guard_only_adds_refusals(self):
        # every form that an earlier round refused is refused still (a strict widening)
        earlier = ["bash run.sh values\\\nremove v1234abcd"]      # refused by the form of round 4 alone
        for command in (list(self.FORMS.values()) + list(self.POWERSHELL.values()) + list(self.ESCAPED.values())
                        + earlier):
            self.assertTrue(value_files.removal_in_command(command), command)

    def test_a_command_without_the_removal_runs(self):
        for command in ("python3 -c 'import json'", "grep -r 'import:' src", "echo forget it"):
            self.assertFalse(value_files.removal_in_command(command), command)

    def test_a_program_cannot_import_its_own_bytes_as_a_value_file(self):
        p = self.file([{"value": NAME, "type": "NAME"}], name="mine.jsonl")
        Path(HOME, "config.json").write_text(json.dumps({"backend": "jsonfile", "allow_plaintext_store": True,
                                                         "value_files": [str(p)]}))
        raw = (json.dumps({"value": "Fremdwert Eingeschleust"}) + "\n").encode()
        r = values.import_bytes(raw, values._path_key(p), "file")
        self.assertEqual([x["origin"] for x in values.rows() if x["id"] == r.id], ["run"])


class Provenance(_Files):
    def test_the_list_shows_each_import_by_id_count_types_and_age_never_a_value(self):
        r = self.imported([{"value": NAME, "type": "NAME"}, {"value": CODE}])
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            cli.main(["list"])
        out = buf.getvalue()
        self.assertIn(f"import:{r.id} · 2 value(s) (SECRET 1, NAME 1)", out)
        for piece in ("Zbigniew", "Quarzel"):
            self.assertNotIn(piece, out)

    def test_the_rules_list_shows_the_imports_pass(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            cli.main(["rules", "list"])
        self.assertIn("imports:import", buf.getvalue())


class SessionStart(_Files):
    def _config(self, files: list) -> dict:
        cfg = {"backend": "jsonfile", "allow_plaintext_store": True, "value_files": [str(f) for f in files]}
        Path(HOME, "config.json").write_text(json.dumps(cfg))
        return load_config()

    def test_a_value_file_is_imported_and_a_new_import_is_named_once(self):
        p = self.file([{"value": NAME, "type": "NAME"}])
        cfg = self._config([p])
        note = values.session_note(cfg)
        self.assertRegex(note, r"masks the values of import:v[0-9a-f]{8} \(1 value")
        self.assertNotIn("Testowski", note)
        self.assertNotIn(p.name, note)
        self.assertIsNone(values.session_note(cfg))
        self.assertEqual(values.rows()[0]["origin"], "file")

    def test_an_edit_that_drops_lines_from_a_value_file_drops_no_value(self):
        p = self.file([{"value": NAME, "type": "NAME"}, {"value": CODE}])
        cfg = self._config([p])
        values.session_note(cfg)
        p.write_text(json.dumps({"value": NAME, "type": "NAME"}) + "\n")
        values.session_note(cfg)
        detect.reset_rules()
        self.assertEqual(len(detect.scan(f"{CODE}", channel="tool")), 1)

    def test_an_import_an_agent_ran_is_named_at_the_next_start(self):
        cfg = self._config([])
        values.session_note(cfg)
        r = self.imported([{"value": NAME, "type": "NAME"}])
        self.assertIn(f"import:{r.id}", values.session_note(cfg))

    def test_a_removed_value_file_import_comes_back_as_the_file_is_now(self):
        p = self.file([{"value": NAME, "type": "NAME"}, {"value": CODE}])
        cfg = self._config([p])
        values.session_note(cfg)
        p.write_text(json.dumps({"value": NAME, "type": "NAME"}) + "\n")
        values.remove_typed([values.rows()[0]["id"]])
        values.session_note(cfg)
        detect.reset_rules()
        self.assertEqual([r["count"] for r in values.rows()], [1])

    def test_a_damaged_import_stops_the_hooks(self):
        r = self.imported([{"value": NAME, "type": "NAME"}])
        (values.IMPORTS / f"{r.id}.jsonl").write_text("not json\n")
        detect.reset_rules()
        with self.assertRaises(values.ValuesError):
            detect.scan("any text")


if __name__ == "__main__":
    unittest.main()
