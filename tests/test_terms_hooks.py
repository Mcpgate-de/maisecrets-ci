"""Terms (maisecrets/terms.py, C26) through the hook entry points: the typed command, the inline marker, a tool result,
a tool call (mask only), the transcript, and every place a term must never be written.

Based on the hook and leak tests of the personal-terms design by @danszymkowiak (tests/test_terms_hooks.py and
tests/test_terms_leaks.py of his fork). A placeholder here is built from OPEN and CLOSE, so the file holds none.

Run: python3 -m unittest tests.test_terms_hooks -v
Synthetic names only.
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one
Path(os.environ["MAISECRETS_HOME"]).mkdir(parents=True, exist_ok=True)
Path(os.environ["MAISECRETS_HOME"], "config.json").write_text('{"backend": "jsonfile", "allow_plaintext_store": true}')

from maisecrets import cli, detect, hooks, incidents, settings, term_files, terms  # noqa: E402
from maisecrets.placeholder import CLOSE, OPEN  # noqa: E402
from maisecrets.vault import HOME  # noqa: E402
import _hygiene  # noqa: E402
from _hygiene import CLAUDE, CODEX  # noqa: E402

NAME = "Zbigniew " + "Testowski"
PIECES = ("zbigniew", "testowsk")          # every piece of the term that would show it, lower case
STATE = ("index.json", "vault.json", "audit.log", "hooks.log", "events.log", "terms.txt", "terms.marked.json",
         ".terms-state", ".terms-cache")
REF_RE = re.compile(re.escape(OPEN) + r"NAME_c\d+" + re.escape(CLOSE))


def _clean() -> None:
    for f in STATE:
        try:
            os.unlink(Path(HOME, f))
        except FileNotFoundError:
            pass
    incidents.clear(Path(HOME))
    hooks._live_cache.clear()
    detect.reset_rules()


def setUpModule():  # noqa: N802 - unittest hook
    Path(HOME, "config.json").write_text('{"backend": "jsonfile", "allow_plaintext_store": true}')


def tearDownModule():  # noqa: N802 - unittest hook
    _clean()
    _hygiene.assert_pristine()


def _write_terms(text: str) -> None:
    terms.PERSONAL.write_text(text, encoding="utf-8")
    os.chmod(terms.PERSONAL, 0o600)
    detect.reset_rules()


def _home_text() -> str:
    """Every file under the home but terms.txt, terms.marked.json and the index .terms-cache (which hold the terms by
    design), as text."""
    parts = []
    for p in Path(HOME).rglob("*"):
        if p.is_file() and p.name not in ("terms.txt", "terms.marked.json", ".terms-cache", "terms.suggested.txt"):
            parts.append(f"--- {p.name}\n" + p.read_bytes().decode("utf-8", errors="replace"))
    return "\n".join(parts)


def _bash(stdout: str, session: str = "S1") -> dict:
    hooks._live_cache.clear()
    return hooks.post_tool({"hook_event_name": "PostToolUse", "tool_name": "Bash", "session_id": session,
                            "tool_input": {"command": "cat notes.txt"}, **CLAUDE,
                            "tool_response": {"stdout": stdout, "stderr": ""}})


def _out(answer: dict) -> str:
    return answer["hookSpecificOutput"]["updatedToolOutput"]["stdout"]


def _prompt(prompt: str, source: str | None = "user", session: str = "S1", client=CLAUDE) -> dict:
    hooks._live_cache.clear()
    payload = {"hook_event_name": "UserPromptSubmit", "prompt": prompt, "session_id": session,
               "transcript_path": "", **client}
    if source is not None:
        payload["source"] = source
    return hooks.user_prompt(payload)


class _Base(unittest.TestCase):
    def setUp(self):
        _clean()
        self.addCleanup(_clean)
        _hygiene.patch(self, hooks, "_clipboard", lambda t: True)

    def assertNoTerm(self, text: str, where: str) -> None:  # noqa: N802 - unittest style
        low = text.lower()
        for piece in PIECES:
            self.assertNotIn(piece, low, f"{where} shows a term")


class TypedCommandTests(_Base):
    def test_term_add_writes_a_private_file_and_the_next_tool_result_is_masked(self):
        out = _prompt(f"/maisecrets:term add {NAME}")
        self.assertEqual(out["decision"], "block", "the prompt carries the name: it never reaches the model")
        self.assertTrue(out["hookSpecificOutput"]["suppressOriginalPrompt"])
        self.assertIn("NAME_1", out["reason"])
        self.assertNoTerm(out["reason"], "the answer")
        if os.name != "nt":
            self.assertEqual(os.stat(terms.PERSONAL).st_mode & 0o777, 0o600)
        masked = _out(_bash(f"Dear {NAME}, your file is ready."))
        self.assertRegex(masked, r"\ADear " + REF_RE.pattern + r", your file is ready\.\Z")

    def test_add_twice_and_remove(self):
        _prompt(f"/maisecrets:term add {NAME}")
        again = _prompt(f"/maisecrets:term add {NAME.upper()}")
        self.assertIn("already on your list (NAME_1", again["reason"])
        gone = _prompt(f"/maisecrets:term remove {NAME}")
        self.assertIn("removed NAME_1", gone["reason"])
        self.assertEqual(_bash(f"Dear {NAME}"), {})

    def test_a_common_word_is_added_with_a_note(self):
        self.assertIn("is a common word", _prompt("/maisecrets:term add Jan")["reason"])
        self.assertNotIn("common word", _prompt(f"/maisecrets:term add {NAME}")["reason"])

    def test_remove_by_the_placeholder_the_person_copied(self):
        _prompt(f"/maisecrets:term add {NAME} | Testowsk*")
        ref = REF_RE.search(_out(_bash("Pan Testowskiego"))).group()
        gone = _prompt(f"/maisecrets:term remove {ref}")
        self.assertIn("removed NAME_1", gone["reason"])
        self.assertEqual(_bash(f"Pan {NAME}"), {})

    def test_remove_by_a_placeholder_of_an_older_version(self):
        _prompt(f"/maisecrets:term add {NAME}")
        old = terms._old_id(terms.parse(terms.PERSONAL.read_text(encoding="utf-8"))[0][0])
        ok, reason, _scrub = terms.term_remove_typed("unrelated text", old)
        self.assertTrue(ok, reason)
        self.assertIn("removed NAME_1", reason)

    def test_codex_form(self):
        out = _prompt(f"maisecrets: term add {NAME}", source=None, client=CODEX)
        self.assertEqual(set(out), {"decision", "reason"})
        self.assertRegex(_out(_bash(NAME)), REF_RE)

    def test_a_prompt_the_client_injected_changes_nothing(self):
        out = _prompt(f"/maisecrets:term add {NAME}", source="scheduled")
        self.assertEqual(out["decision"], "block")
        self.assertIn("this one came from a scheduled task, so nothing was changed", out["reason"])
        self.assertFalse(terms.PERSONAL.exists())
        _prompt(f"/maisecrets:term add {NAME}")
        out = _prompt(f"/maisecrets:term remove {NAME}", source="loop")
        self.assertIn("nothing was changed", out["reason"])
        self.assertRegex(_out(_bash(NAME)), REF_RE)

    def test_the_name_of_a_term_command_is_masked_in_the_transcript(self):
        tmp = Path(tempfile.mkdtemp(prefix="transcript-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        path = tmp / "session.jsonl"
        record = json.dumps({"type": "user", "message": {"content": f"/maisecrets:term add {NAME}"}}) + "\n"
        path.write_bytes(record.encode("utf-8"))      # no newline translation: Windows wrote \r\n
        with mock.patch.object(hooks, "_scrub_transcript_later", lambda *a, **k: None):
            hooks.user_prompt({"hook_event_name": "UserPromptSubmit", "prompt": f"/maisecrets:term add {NAME}",
                               "session_id": "S1", "source": "user", "transcript_path": str(path), **CLAUDE})
        self.assertNoTerm(path.read_text(encoding="utf-8"), "the transcript")
        self.assertEqual(len(path.read_bytes()), len(record.encode()), "masked in place, same length")

    def test_a_term_command_without_add_or_remove_is_blocked_with_the_usage(self):
        out = _prompt(f"/maisecrets:term {NAME}")
        self.assertEqual(out["decision"], "block")
        self.assertIn("/maisecrets:term add NAME", out["reason"])
        self.assertFalse(terms.PERSONAL.exists())

    def test_a_removal_in_a_tool_call_is_refused(self):
        # a nested client would type it for the model (C22); adding is stricter and stays allowed
        self.assertTrue(settings.IN_A_COMMAND_RE.search(f"claude -p '/maisecrets:term remove {NAME}'"))
        self.assertTrue(settings.IN_A_COMMAND_RE.search("codex exec 'maisecrets: term remove X'"))
        self.assertFalse(settings.IN_A_COMMAND_RE.search(f"claude -p '/maisecrets:term add {NAME}'"))

    def test_the_mod_leaves_a_term_command_to_the_hook(self):
        _prompt(f"/maisecrets:term add {NAME}")
        self.assertEqual(hooks.rewrite_prompt({"prompt": f"/maisecrets:term remove {NAME}", "session_id": "S1",
                                               "cwd": ""}), {})


class GateReviewCommandTests(_Base):
    """The typed command findings of the gate review of block 2."""

    def test_a_full_name_also_adds_the_surname_with_any_ending(self):
        out = _prompt("/maisecrets:term add Jan Testowski")
        self.assertIn("Also added: 2 variant(s)", out["reason"])
        self.assertIn("/maisecrets:term shows them", out["reason"])
        self.assertIn("The first name alone stays visible", out["reason"])
        self.assertNotIn("testowsk", out["reason"].lower())
        self.assertIn("Jan Testowski | Testowski | Testowskis\n", terms.PERSONAL.read_text(encoding="utf-8"))
        for text in ("Herr Testowski", "Testowskis Bericht", "Testowski, Jan", "J. Testowski", "jan_testowski.pdf",
                     "Jan-Testowski", "jan.testowski"):
            with self.subTest(text=text):
                self.assertNotIn("testowsk", _out(_bash(text)).lower())
        self.assertEqual(_bash("Jan alone"), {}, "the first name alone stays visible, as the answer says")

    def test_the_surname_is_a_whole_word_never_a_stem(self):
        # 243 of 290 common surnames are the start of an ordinary word: Koch*, Lang*, Wolf*, Cook* (round 2)
        _prompt("/maisecrets:term add Anna Koch")
        self.assertIn("Anna Koch | Koch | Kochs\n", terms.PERSONAL.read_text(encoding="utf-8"))
        self.assertEqual(_bash("Kochen und Kochbuch"), {})
        self.assertNotIn("Koch", _out(_bash("Herr Koch, Kochs Akte")))

    def test_no_surname_for_a_short_or_common_last_word_or_one_word(self):
        _prompt("/maisecrets:term add Anna Li")
        _prompt("/maisecrets:term add Testowski")
        self.assertNotIn("*", terms.PERSONAL.read_text(encoding="utf-8").split("README, section Terms.")[1])

    def test_near_misses_of_the_command_are_blocked_with_the_usage(self):
        for typed in (f"maisecrets: terms add {NAME}", f"/maisecrets:terms add {NAME}", f"maisecrets term add {NAME}",
                      f"/maisecrets:terms remove {NAME}"):
            with self.subTest(typed=typed):
                out = _prompt(typed)
                self.assertEqual(out["decision"], "block")
                self.assertIn("/maisecrets:term add NAME", out["reason"])
                self.assertNoTerm(json.dumps(out), "the answer")
        self.assertFalse(terms.PERSONAL.exists(), "a near miss changes nothing")
        self.assertIsNone(terms.parse_command("maisecrets terms are a feature"))

    def test_every_form_of_the_name_is_scrubbed_from_the_transcript(self):
        for typed in ("/maisecrets:term add Zbigniew  Testowski", "/maisecrets:term add Zbigniew\tTestowski",
                      "/maisecrets:term add Zbigniew\nTestowski", "/maisecrets:term add Li Wu"):
            with self.subTest(typed=typed):
                _clean()
                tmp = Path(tempfile.mkdtemp(prefix="transcript-"))
                self.addCleanup(shutil.rmtree, tmp, True)
                path = tmp / "session.jsonl"
                path.write_text(json.dumps({"type": "user", "message": {"content": typed}}) + "\n", encoding="utf-8")
                with mock.patch.object(hooks, "_scrub_transcript_later", lambda *a, **k: None):
                    hooks.user_prompt({"hook_event_name": "UserPromptSubmit", "prompt": typed, "session_id": "S1",
                                       "source": "user", "transcript_path": str(path), **CLAUDE})
                left = path.read_text(encoding="utf-8").lower()
                for piece in ("zbigniew", "testowsk", "li wu"):
                    self.assertNotIn(piece, left)

    def test_a_subagent_prompt_changes_no_term(self):
        hooks._live_cache.clear()
        out = hooks.user_prompt({"hook_event_name": "UserPromptSubmit", "prompt": f"/maisecrets:term add {NAME}",
                                 "session_id": "S1", "source": "user", "agent_id": "a1", "transcript_path": "",
                                 **CLAUDE})
        self.assertIn("nothing was changed", out["reason"])
        self.assertFalse(terms.PERSONAL.exists())

    def test_a_claude_add_without_a_source_has_the_floor_of_a_team_list(self):
        out = _prompt("/maisecrets:term add the", source=None)
        self.assertIn("not added (a common word (rules/term_stoplist.txt); a prompt without a source may not come "
                      "from you", out["reason"])
        self.assertIn("needs a stem of at least 5 letters; a prompt", _prompt("/maisecrets:term add Kow*", source=None)[
            "reason"])
        self.assertFalse(terms.PERSONAL.exists())

    def test_a_codex_add_follows_the_rules_of_your_own_list(self):
        # Codex never sends a source (round 2): its adds are the person's, as in Claude Code
        self.assertIn("is a common word", _prompt("maisecrets: term add Jan", source=None, client=CODEX)["reason"])
        self.assertTrue(terms.PERSONAL.exists())
        added = _prompt(f"maisecrets: term add {NAME}", source=None, client=CODEX)
        self.assertIn("is on your list now", added["reason"])

    def test_the_removal_names_the_variant_count(self):
        _prompt(f"/maisecrets:term add {NAME}")
        self.assertIn("removed NAME_1 (3 variants)", _prompt(f"/maisecrets:term remove {NAME}")["reason"])


class TermHookTests(_Base):
    def setUp(self):
        super().setUp()
        _write_terms(f"PERSON_A  {NAME} | Testowsk*\nCASE_A  *sygn-0042*\n")

    def test_every_spelling_of_an_entity_gets_its_one_placeholder(self):
        text = _out(_bash(f"Pan Testowskiego i {NAME}, akta X-sygn-0042-B; TESTOWSKI."))
        refs = REF_RE.findall(text)
        self.assertEqual(len(refs), 4)
        person, case = refs[0], refs[2]
        self.assertEqual(refs, [person, person, case, person], "one entity, one placeholder")
        self.assertNotEqual(person, case)
        self.assertNoTerm(text, "the tool result")
        self.assertNotIn("sygn", text)
        again = REF_RE.findall(_out(_bash(f"{NAME}", session="S2")))
        self.assertEqual(again, refs[:1], "the same placeholder in another session while the entry lives")

    def test_the_term_is_never_copied_into_the_store_or_the_index(self):
        _bash(f"{NAME} and Testowskiego")
        self.assertNoTerm(_home_text(), "a file of the home")
        store = json.loads(Path(HOME, "vault.json").read_text(encoding="utf-8"))
        values = [v for v in json.dumps(store).split('"') if v.startswith(terms.STORE_PREFIX)]
        self.assertTrue(values, "the store holds the entity id")

    def test_mask_only_a_placeholder_in_a_tool_call_stays_as_written(self):
        ref = REF_RE.search(_out(_bash(NAME))).group()
        for tool, tool_input in (("Bash", {"command": f"echo 'Dear {ref}' > letter.txt"}),
                                 ("Write", {"file_path": "/tmp/letter.txt", "content": f"Dear {ref},\n"}),
                                 ("mcp__mail__draft", {"to": "x", "body": f"Dear {ref}"})):
            with self.subTest(tool=tool):
                out = hooks.pre_tool({"hook_event_name": "PreToolUse", "tool_name": tool, "session_id": "S1",
                                      "transcript_path": "", **CLAUDE, "tool_input": tool_input, "cwd": "/tmp"})
                self.assertNotEqual(out.get("hookSpecificOutput", {}).get("permissionDecision"), "deny", out)
                self.assertNoTerm(json.dumps(out), "the tool call")
                updated = out.get("hookSpecificOutput", {}).get("updatedInput")
                if updated is not None:
                    self.assertEqual(updated, tool_input)

    def test_a_private_use_character_in_the_content_stays_as_it_is(self):
        ref = REF_RE.search(_out(_bash(NAME))).group()
        tool_input = {"file_path": "/tmp/x.txt", "content": f"Dear {ref}, \ue000 and \ue001 stay"}
        echo = {"hookSpecificOutput": {"hookEventName": "PreToolUse", "updatedInput": None}}

        def fake(payload):
            return {"hookSpecificOutput": dict(echo["hookSpecificOutput"], updatedInput=payload["tool_input"])}
        with mock.patch.object(hooks, "_pre_tool", fake):
            out = hooks.pre_tool({"hook_event_name": "PreToolUse", "tool_name": "Write", "session_id": "S1",
                                  "transcript_path": "", **CLAUDE, "tool_input": tool_input, "cwd": "/tmp"})
        self.assertEqual(out["hookSpecificOutput"]["updatedInput"], tool_input)

    def test_every_private_use_character_in_the_content_falls_back_or_denies(self):
        ref = REF_RE.search(_out(_bash(NAME))).group()
        bmp = "".join(chr(c) for c in range(0xE000, 0xF900))
        planes = bmp + "".join(chr(c) for r in ((0xF0000, 0xFFFFE), (0x100000, 0x10FFFE)) for c in range(*r))

        def call(content):
            return hooks.pre_tool({"hook_event_name": "PreToolUse", "tool_name": "Write", "session_id": "S1",
                                   "transcript_path": "", **CLAUDE, "cwd": "/tmp",
                                   "tool_input": {"file_path": "/tmp/x.txt", "content": f"Dear {ref} {content}"}})
        self.assertNotEqual(call(bmp).get("hookSpecificOutput", {}).get("permissionDecision"), "deny",
                            "plane 15 takes over")
        out = call(planes)
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertIn("every private-use character", out["hookSpecificOutput"]["permissionDecisionReason"])

    def test_the_model_is_told_the_placeholder_is_never_resolved(self):
        out = _bash(NAME)
        self.assertIn("never puts the name back", out["hookSpecificOutput"]["additionalContext"])

    def test_a_term_in_a_typed_prompt_does_not_reach_the_model(self):
        out = _prompt(f"write to {NAME}")
        self.assertEqual(out.get("decision"), "block")
        self.assertNoTerm(json.dumps(out), "the prompt answer")
        mod = hooks.rewrite_prompt({"prompt": f"write to {NAME}", "session_id": "S1", "cwd": ""})
        self.assertRegex(mod["text"], r"\Awrite to " + REF_RE.pattern + r"\Z")

    def test_a_shape_keeps_its_span_before_a_term(self):
        _write_terms("PERSON_A  *testowski*\n")
        token = "glpat-" + "TestowskiXyz1234567890"
        self.assertEqual([m.type for m in detect.scan(f"token {token} and Testowski")], ["SECRET", "NAME"])

    def test_a_bad_terms_file_fails_closed_without_a_term(self):
        _write_terms(f"PERSON_A  {NAME}\nPERSON_A  Testowsk*\n")
        out = hooks._post_tool_guarded({"hook_event_name": "PostToolUse", "tool_name": "Bash", "session_id": "S1",
                                        "tool_input": {"command": "cat notes.txt"}, **CLAUDE,
                                        "tool_response": {"stdout": NAME, "stderr": ""}})
        self.assertIn("terms.txt: line 2", json.dumps(out))
        self.assertNoTerm(json.dumps(out), "the answer of a hook that failed closed")
        self.assertNoTerm(_home_text(), "the incident record and the logs")


class StoredValueTests(_Base):
    """A listed term inside a value the store holds (a password without a shape): the stored value is taken out
    whole, before the term matcher can split it (gate review of block 2, B1)."""
    VALUE = "Testowski#Sommer" + "2024"
    REST = "sommer2024"

    def setUp(self):
        super().setUp()
        self.assertEqual(_prompt(f"password: {self.VALUE}")["decision"], "block")
        _write_terms("PERSON_A  Testowski\n")
        self.secret = re.compile(re.escape(OPEN) + r"SECRET_c\d+" + re.escape(CLOSE))

    def test_a_tool_result_masks_the_stored_value_whole(self):
        for text in (self.VALUE, f"the value is {self.VALUE} ok", f"echo {self.VALUE}"):
            with self.subTest(text=text):
                out = _out(_bash(text))
                self.assertNotIn(self.REST, out.lower(), "the rest of the stored value is in clear")
                self.assertRegex(out, self.secret)

    def test_a_prompt_and_the_mod_mask_the_stored_value_whole(self):
        out = _prompt(f"try {self.VALUE} again")
        self.assertEqual(out["decision"], "block")
        sent = hooks.take_pending("S1")
        self.assertNotIn(self.REST, sent.lower(), "/maisecrets:send would send the rest")
        self.assertRegex(sent, r"\Atry " + self.secret.pattern + r" again\Z")
        mod = hooks.rewrite_prompt({"prompt": f"try {self.VALUE} again", "session_id": "S1", "cwd": ""})
        self.assertRegex(mod["text"], r"\Atry " + self.secret.pattern + r" again\Z")
        self.assertEqual(mod["count"], 1, "the notice counts the value once, not the name inside it too")

    def test_a_failed_call_cleans_the_stored_value_whole_from_the_transcript(self):
        tmp = Path(tempfile.mkdtemp(prefix="transcript-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        path = tmp / "session.jsonl"
        path.write_text(json.dumps({"type": "tool_result", "content": f"bad: {self.VALUE}"}) + "\n", encoding="utf-8")
        with mock.patch.object(hooks, "_scrub_transcript_later", lambda *a, **k: None):
            out = hooks.post_tool_failure({"hook_event_name": "PostToolUseFailure", "tool_name": "Bash",
                                           "session_id": "S1", "transcript_path": str(path), **CLAUDE,
                                           "tool_input": {"command": "x"}, "error": f"bad: {self.VALUE}"})
        self.assertNotIn(self.REST, json.dumps(out).lower())
        self.assertNotIn(self.REST, path.read_text(encoding="utf-8").lower(), "the transcript keeps the rest")


class ReviewRoundOneTests(_Base):
    """The findings of the two review gates on the rebase that a test can hold."""

    def test_a_union_that_holds_a_term_stays_a_term(self):
        # Gate A 8 / Gate B 2: a stored value joins a token hit and a term hit; the union kept the token's kind, and
        # the store kept the name in a value that a command could resolve
        text = "ghp_Ab12Qx7Lm2 Testowski"
        token = detect.Match("github-pat", "SECRET", text[:14], 0, 14)
        term = detect.Match("term:abc", "NAME", "Testowski", 15, 24)
        stored = []

        class FakeVault:
            def put_many(self, items, session=None, tool=False):
                stored.extend(items)
                return [None] * len(items)
        with mock.patch.object(hooks, "_exact_spans", lambda *a, **k: [(10, 19)]):
            got = hooks._longest_wins(text, [token, term], FakeVault(), "S1", [])
        self.assertEqual([(m.kind, m.start, m.end) for m in got], [("term:abc", 0, 24)])

    def test_an_expired_last_mark_leaves_no_file(self):
        # Gate B 5: an empty terms.marked.json kept term_files.present() true, and each hook built the terms index
        terms.take_markers(f"letter to {{{{{NAME}}}}}", 60)
        self.assertTrue(terms.MARKED.exists())
        self.assertEqual(terms._marked(now=10 ** 12), [])
        self.assertFalse(terms.MARKED.exists())
        from maisecrets import term_files
        term_files.forget()
        self.assertFalse(term_files.present())

    def test_a_team_list_that_is_a_link_is_refused(self):
        # Gate B 7: a rule folder is read without links (C25); a *.terms link was read
        team = Path(tempfile.mkdtemp(prefix="team-"))
        self.addCleanup(shutil.rmtree, team, True)
        outside = Path(tempfile.mkdtemp(prefix="outside-"))
        self.addCleanup(shutil.rmtree, outside, True)
        (outside / "x.terms").write_text("CLIENT_A  Zbigniew Testowski\n", encoding="utf-8")
        (team / "x.terms").symlink_to(outside / "x.terms")
        loaded = terms.load({"rule_dirs": [str(team)]})
        self.assertEqual(loaded.entities, [])
        self.assertEqual([r.reason for r in loaded.refused], ["a symbolic link (a rule folder is read without links)"])

    def test_a_new_stop_list_parses_the_team_lists_again(self):
        # Gate B 8: the cache key did not hold the stop list, so a word the new floor refuses stayed in the index
        team = [("team/x.terms", b"CLIENT_A  Zbigniew Testowski\n")]
        key = terms._cache_key(None, team)
        with mock.patch.object(terms, "_stop_digest", lambda: "another stop list"):
            self.assertNotEqual(terms._cache_key(None, team), key)

    def test_a_prompt_that_names_a_secret_does_not_load_the_terms_module(self):
        # Gate B 4: the prefilter took any `ecret` near the start; it is the head of the command patterns now
        code = ("import sys; sys.path.insert(0, %r); from maisecrets import term_files; "
                "a = term_files.parse_command('secret rotation is due today'); "
                "print(a, 'maisecrets.terms' in sys.modules); "
                "print(term_files.parse_command('  /MAISECRETS:term add Jan Kowalski'))" % str(ROOT))
        r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, env=dict(os.environ),
                           timeout=60)
        self.assertEqual(r.stdout.split("\n")[:2], ["None False", "('add', 'Jan Kowalski')"], r.stderr[-400:])


class ReviewRoundTwoTests(_Base):
    """The findings of the second round of both review gates on the rebase."""

    def test_a_term_that_a_stored_value_equals_stays_a_term(self):
        # Gate A, round 2: an address stored before the list named it kept its resolvable placeholder
        address = "zbigniew.testowski" + "@" + "firma-xyz.de"
        first = _out(_bash(f"mail {address}"))
        self.assertRegex(first, re.escape(OPEN) + r"EMAIL_c\d+")
        _write_terms(f"EMAIL_ZT  {address}\n")
        out = _out(_bash(f"again {address}"))
        refs = re.findall(re.escape(OPEN) + r"([A-Z]+_c\d+)", out)
        self.assertEqual(len(refs), 1, out)
        index = json.loads(Path(HOME, "index.json").read_text(encoding="utf-8"))["entries"]
        self.assertTrue(terms.is_term_kind(index[refs[0]]["kind"]), "the listed address is a term now: mask only")

    def test_a_secret_that_a_union_with_a_term_absorbs_is_stored_too(self):
        # Gate B, round 2: the union became a term, and the secret in it had no entry of its own
        text = "Hunter2Qx77 Zbigniew Testowski"
        secret = detect.Match("ds-keyword-colon", "SECRET", "Hunter2Qx77", 0, 11)
        term = detect.Match("term:abc", "NAME", "Zbigniew Testowski", 12, 30)
        stored = []

        class FakeVault:
            def put_many(self, items, session=None, tool=False):
                stored.extend(items)
                return [None] * len(items)
        with mock.patch.object(hooks, "_exact_spans", lambda *a, **k: [(7, 16)]):
            got = hooks._longest_wins(text, [secret, term], FakeVault(), "S1", [])
        self.assertEqual([(m.kind, m.start, m.end) for m in got], [("term:abc", 0, 30)])
        self.assertEqual(stored, [("Hunter2Qx77", "SECRET", "ds-keyword-colon")])

    @unittest.skipUnless(hasattr(os, "mkfifo"), "no FIFO on this system")
    def test_a_team_list_swapped_for_a_fifo_never_holds_the_hook(self):
        # Gate A, round 2: the size check and the read were two steps; a FIFO in place of the file held the read
        team = Path(tempfile.mkdtemp(prefix="team-"))
        self.addCleanup(shutil.rmtree, team, True)
        os.mkfifo(team / "x.terms")
        # the listing saw a regular file; the read finds the FIFO
        code = ("import sys; from pathlib import Path; sys.path.insert(0, %r); sys.path.insert(0, %r); "
                "import _isolate; "
                "from maisecrets import terms, term_files; "
                "term_files.team_files = lambda cfg: [('team/x.terms', Path(%r) / 'x.terms')]; "
                "print([r.reason for r in terms._team_sources({})[1]])" % (str(ROOT), str(ROOT / "tests"), str(team)))
        r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, env=dict(os.environ),
                           timeout=60)
        self.assertEqual(r.stdout.strip(), "['a file that cannot be read']", r.stderr[-400:])

    def test_a_name_with_a_capital_inside_a_word_or_spaces_in_the_braces_is_marked(self):
        # Gate B, round 2: the template rule of round 1 let these names go to the model in clear
        for text in ("{{Ronald McDonald}}", "{{Jan DeVries}}", "{{ Jan Kowalczyk }}", "{{Anna-Lena MacLeod}}"):
            with self.subTest(text=text):
                self.assertEqual(len(terms.markers(f"write to {text} now")), 1)
        for text in ("{{FirstName}}", "{{ Title }}"):
            self.assertEqual(terms.markers(f"hello {text}"), [])


class QuietValueTests(_Base):
    """A word-like value that a label rule took in a tool result is quiet: a typed prompt does not hunt it
    (vault.is_quiet). The longest-span rule must not drop a term hit inside it there, or the name went out with it."""

    def test_a_term_inside_a_quiet_value_is_masked_in_a_typed_prompt(self):
        # stored quiet before the list named the word inside it; then the list gets the name
        value = "testowski" + "haus"
        _out(_bash(f"password: {value}"))
        index = json.loads(Path(HOME, "index.json").read_text(encoding="utf-8"))["entries"]
        self.assertTrue(any(m.get("quiet") for m in index.values()), "the scenario needs a quiet entry")
        _write_terms("PERSON_A  *testowski*\n")
        self.assertEqual(_prompt(f"the house is {value} now")["decision"], "block")
        self.assertNotIn("testowski", hooks.take_pending("S1").lower())
        mod = hooks.rewrite_prompt({"prompt": f"the house is {value} now", "session_id": "S1", "cwd": ""})
        self.assertNotIn("testowski", mod["text"].lower())


class LongestSpanTests(_Base):
    """A value this session resolved inside a longer token the detector knows (C2): the whole token is taken out,
    never the value alone with the rest of the token in clear (gate review of block 2, round 2, HIGH-1)."""
    TOKENS = (("ghp_" + "Ab12", "Qx7Lm2" + "Wv9Tk4", "Cd34Ef56Gh78" + "Ij90Kl12"),
              ("AKIA", "QWERTYUI" + "OPAS", "DFGH"))

    def setUp(self):
        super().setUp()
        self.secret = re.compile(re.escape(OPEN) + r"SECRET_c\d+" + re.escape(CLOSE))
        self.cases = []
        for head, value, tail in self.TOKENS:
            self.assertEqual(_prompt(f"password: {value}")["decision"], "block")
            ref = self.secret.search(hooks.take_pending("S1")).group()
            hooks.pre_tool({"hook_event_name": "PreToolUse", "tool_name": "Bash", "session_id": "S1",
                            "transcript_path": "", **CLAUDE, "tool_input": {"command": f"echo {ref}"}, "cwd": "/tmp"})
            self.cases.append((head + value + tail, head, tail))
        self.assertGreaterEqual(len(hooks._resolved_values(hooks.Vault(hooks.load_config()), "S1")), 2,
                                "both values are resolved in S1")

    def assertWhole(self, text, token, head, tail, where):  # noqa: N802 - unittest style
        self.assertNotIn(tail.lower(), text.lower(), f"{where}: the rest of the token is in clear")
        self.assertNotIn(head.lower(), text.lower(), f"{where}: the start of the token is in clear")

    def test_a_tool_result_takes_the_whole_token(self):
        for token, head, tail in self.cases:
            with self.subTest(token=head):
                out = _out(_bash(f"token {token} end"))
                self.assertWhole(out, token, head, tail, "the tool result")
                self.assertRegex(out, r"\Atoken " + self.secret.pattern + r" end\Z")

    def test_with_a_term_in_the_text_a_tool_result_takes_the_whole_token(self):
        # a term hit in the text turns on the longest-span rule (hooks._longest_wins); the token still goes whole
        _write_terms("PERSON_A  Testowski\n")
        for token, head, tail in self.cases:
            with self.subTest(token=head):
                out = _out(_bash(f"Testowski: token {token} end"))
                self.assertWhole(out, token, head, tail, "the tool result")
                self.assertRegex(out, r"\A" + REF_RE.pattern + r": token " + self.secret.pattern + r" end\Z")

    def test_the_prompt_and_the_mod_take_the_whole_token(self):
        for token, head, tail in self.cases:
            with self.subTest(token=head):
                self.assertEqual(_prompt(f"the new token is {token} ok")["decision"], "block")
                self.assertWhole(hooks.take_pending("S1"), token, head, tail, "/maisecrets:send")
                mod = hooks.rewrite_prompt({"prompt": f"the new token is {token} ok", "session_id": "S1", "cwd": ""})
                self.assertWhole(mod["text"], token, head, tail, "the mod")
                self.assertEqual(mod["count"], 1, "the notice counts the token once")

    def test_a_failed_call_records_the_whole_token(self):
        for token, head, tail in self.cases:
            with self.subTest(token=head):
                tmp = Path(tempfile.mkdtemp(prefix="transcript-"))
                self.addCleanup(shutil.rmtree, tmp, True)
                path = tmp / "session.jsonl"
                record = json.dumps({"type": "tool_result", "content": f"bad: {token}"}) + "\n"
                path.write_text(record, encoding="utf-8")
                with mock.patch.object(hooks, "_scrub_transcript_later", lambda *a, **k: None):
                    hooks.post_tool_failure({"hook_event_name": "PostToolUseFailure", "tool_name": "Bash",
                                             "session_id": "S1", "transcript_path": str(path), **CLAUDE,
                                             "tool_input": {"command": "x"}, "error": f"bad: {token}"})
                self.assertWhole(path.read_text(encoding="utf-8"), token, head, tail, "the transcript")


class ShapedTermTests(_Base):
    """A listed term that a built-in rule finds too keeps the rule's type, but it is a term: the store keeps the
    entity id, and the placeholder is never resolved (codex review of block 2, HIGH 2)."""
    # not example.com: the email rule leaves the documentation domains alone, so the overlap would not happen
    EMAIL = "zbigniew.testowski" + "@" + "firma-xyz.de"
    PHONE = "+49 30 " + "98765432"
    CASE = "glpat-" + "Testowski0123456789x"

    def setUp(self):
        super().setUp()
        _write_terms(f"EMAIL_ZT  {self.EMAIL}\nPHONE_ZT  {self.PHONE}\nCASE_ZT  {self.CASE}\n")

    def test_the_store_keeps_the_entity_and_the_placeholder_stays(self):
        out = _out(_bash(f"mail {self.EMAIL}, call {self.PHONE}, case {self.CASE}."))
        for value in (self.EMAIL, self.PHONE, self.CASE):
            self.assertNotIn(value, out)
        refs = re.findall(re.escape(OPEN) + r"[A-Z]+_c\d+(?::[^" + CLOSE + r"]*)?" + re.escape(CLOSE), out)
        self.assertEqual(len(refs), 3, out)
        store = Path(HOME, "vault.json").read_text(encoding="utf-8")
        index = json.loads(Path(HOME, "index.json").read_text(encoding="utf-8"))["entries"]
        for value in (self.EMAIL, self.PHONE, self.CASE, "testowski"):
            self.assertNotIn(value, store, "the store keeps the entity id, never the term")
        self.assertTrue(all(terms.is_term_kind(m["kind"]) for m in index.values()), index)
        self.assertIn("SECRET_c", out, "the rule keeps its type")
        for ref in refs:
            with self.subTest(ref=ref):
                tool_input = {"command": f"echo {ref} > note.txt"}
                answer = hooks.pre_tool({"hook_event_name": "PreToolUse", "tool_name": "Bash", "session_id": "S1",
                                         "transcript_path": "", **CLAUDE, "tool_input": tool_input, "cwd": "/tmp"})
                updated = answer.get("hookSpecificOutput", {}).get("updatedInput")
                self.assertIn(updated, (None, tool_input), "a term placeholder is never resolved")
                self.assertNotIn("testowski", json.dumps(answer).lower())


class MarkerHookTests(_Base):
    def test_a_marked_name_is_masked_in_its_prompt_and_in_later_output(self):
        out = _prompt(f"draft a letter to {{{{{NAME}}}}}; {NAME} asked for it")
        self.assertEqual(out["decision"], "block")
        self.assertNoTerm(json.dumps(out), "the prompt answer")
        sent = hooks.take_pending("S1")
        self.assertRegex(sent, r"\Adraft a letter to (" + REF_RE.pattern + r"); \1 asked for it\Z",
                         "/maisecrets:send sends the name as its placeholder, without the braces")
        self.assertRegex(_out(_bash(f"Re: {NAME}")), r"\ARe: " + REF_RE.pattern + r"\Z")
        self.assertFalse(terms.PERSONAL.exists(), "a mark is not permanent: only term add writes terms.txt")

    def test_a_mark_after_a_scan_without_any_list_is_masked_in_the_same_process(self):
        # the process looked for a list before the mark existed (term_files.present is kept per process): the mark
        # makes the next scan read the lists again, in the prompt that holds it and in a later tool result
        self.assertFalse(terms.MARKED.exists())
        self.assertEqual(detect.scan(f"nothing to mask, {NAME}"), [])
        out = _prompt(f"draft a letter to {{{{{NAME}}}}}; {NAME} asked for it")
        self.assertEqual(out["decision"], "block")
        self.assertRegex(hooks.take_pending("S1"), r"\Adraft a letter to (" + REF_RE.pattern + r"); \1 asked for it\Z")
        self.assertRegex(_out(_bash(f"Re: {NAME}")), r"\ARe: " + REF_RE.pattern + r"\Z")

    def test_without_any_list_a_scan_does_not_load_the_terms_module(self):
        code = ("import sys; sys.path.insert(0, %r); from maisecrets import detect, hooks; "
                "detect.scan('Jan wrote to the team'); print('maisecrets.terms' in sys.modules)" % str(ROOT))
        r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, env=dict(os.environ),
                           timeout=60)
        self.assertEqual(r.stdout.strip(), "False", r.stderr[-400:])
        _write_terms("PERSON_A  Testowski\n")
        r = subprocess.run([sys.executable, "-c", code.replace("Jan wrote", "Testowski wrote")], capture_output=True,
                           text=True, env=dict(os.environ), timeout=60)
        self.assertEqual(r.stdout.strip(), "True", r.stderr[-400:])

    def test_a_template_without_any_list_does_not_load_the_terms_module(self):
        # a `{{` of a template is no marker: without a list the prompt hook and the mod do not import terms.py (3 to 7
        # ms per prompt). A marker does, and it marks the name (the control)
        code = ("import json, sys; sys.path.insert(0, %r); from maisecrets import hooks; p = json.loads(sys.argv[1]); "
                "hooks._clipboard = lambda t: True; hooks.user_prompt(p); "
                "hooks.rewrite_prompt({**p, 'origin': 'composer'}); "
                "print('maisecrets.terms' in sys.modules)" % str(ROOT))

        def loads(prompt: str) -> str:
            payload = {"hook_event_name": "UserPromptSubmit", "prompt": prompt, "session_id": "S1",
                       "transcript_path": "", "source": "user", **CLAUDE}
            r = subprocess.run([sys.executable, "-c", code, json.dumps(payload)], capture_output=True, text=True,
                               env=dict(os.environ), timeout=60)
            return r.stdout.strip() or r.stderr[-400:]
        self.assertEqual(loads("set {{ .Values.image.tag }}, {{ item }}, {{FirstName}}, {{x}} and {{a b c d e f}}"),
                         "False")
        self.assertFalse(terms.MARKED.exists())
        self.assertEqual(loads(f"letter to {{{{{NAME}}}}}"), "True")
        self.assertTrue(terms.MARKED.exists(), "the marker marked the name")

    def test_the_form_check_and_the_markers_agree(self):
        # term_files.marker_forms decides whether terms.py loads; terms.markers adds only the stoplist to it
        for text in ("{{Jan Kowalski}}", "{{ .Values.x }}", "{{ item }}", "{{FirstName}}", "{{ Title }}", "{{A}}",
                     "{{The}}", "{{Anna-Lena MacLeod}}", "{{a b}}", "{{Jan 2}}", "{{" + "Ab " * 6 + "}}"):
            with self.subTest(text):
                forms = [(a, b, " ".join(w)) for a, b, w in term_files.marker_forms(f"see {text} now")]
                found = terms.markers(f"see {text} now")
                self.assertTrue(set(found) <= set(forms))
                if text != "{{The}}":
                    self.assertEqual(found, forms)

    def test_the_mod_takes_the_marker_out(self):
        mod = hooks.rewrite_prompt({"prompt": f"letter to {{{{{NAME}}}}}", "session_id": "S1", "cwd": "",
                                    "origin": "composer"})
        self.assertRegex(mod["text"], r"\Aletter to " + REF_RE.pattern + r"\Z")

    def test_the_mod_takes_a_marker_only_from_the_composer(self):
        for origin in ("sdk", None):
            with self.subTest(origin=origin):
                payload = {"prompt": f"letter to {{{{{NAME}}}}}", "session_id": "S1", "cwd": ""}
                if origin:
                    payload["origin"] = origin
                self.assertEqual(hooks.rewrite_prompt(payload), {})
                self.assertFalse(terms.MARKED.exists(), "a prompt a program sent marks no name")

    def test_one_letter_or_one_common_word_stays_text(self):
        self.assertEqual(terms.markers("see {{A}} and {{The}} and {{Montag}}"), [])
        self.assertEqual([n for _a, _b, n in terms.markers("see {{Testowski}}")], ["Testowski"])

    def test_a_marker_from_the_client_or_a_template_stays_text(self):
        self.assertEqual(_prompt(f"letter to {{{{{NAME}}}}}", source="scheduled"), {})
        self.assertFalse(terms.MARKED.exists())
        self.assertEqual(_prompt("set {{ .Values.image.tag }} and {{ item }}"), {})
        self.assertFalse(terms.MARKED.exists())


class LeakTests(_Base):
    def _cli(self, *argv: str) -> str:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                cli.main(list(argv))
            except SystemExit:
                pass
        return out.getvalue() + err.getvalue()

    def test_status_list_audit_report_and_terms_show_no_term(self):
        _prompt(f"/maisecrets:term add {NAME} | Testowsk*")
        _bash("Pan Testowskiego")
        _prompt("see {{Anna Testowska}}")
        for argv in (("list",), ("status",), ("audit",), ("report",), ("report", "last"), ("terms",), ("rules",)):
            with self.subTest(argv):
                self.assertNoTerm(self._cli(*argv), "maisecrets " + " ".join(argv))
        self.assertIn("terms: 1 of your own, 0 from 0 team file(s), 1 marked in prompts", self._cli("status"))
        self.assertNoTerm(_home_text(), "a file of the home")

    def test_suggest_never_prints_a_name_and_writes_a_private_proposal(self):
        tmp = Path(tempfile.mkdtemp(prefix="suggest-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        self.addCleanup(lambda: terms.SUGGESTED.unlink() if terms.SUGGESTED.exists() else None)
        doc = tmp / "letter.txt"
        doc.write_text(f"Sehr geehrter Herr {NAME},\nPan Testowskiego i Testowskiej.\nName: Anna Kowalska\n",
                       encoding="utf-8")
        piped = self._cli("terms", "suggest", str(doc))
        self.assertIn("candidate(s)", piped)
        self.assertNoTerm(piped, "suggest into a pipe")
        buf = io.StringIO()
        buf.isatty = lambda: True          # a terminal, or a pseudo-terminal an agent opened: the same
        with contextlib.redirect_stdout(buf):
            cli.main(["terms", "suggest", str(doc)])
        self.assertNoTerm(buf.getvalue(), "suggest into a terminal")
        self.assertNotIn("Kowalska", buf.getvalue())
        self.assertIn(str(terms.SUGGESTED), buf.getvalue())
        shown = terms.SUGGESTED.read_text(encoding="utf-8")
        if os.name != "nt":
            self.assertEqual(os.stat(terms.SUGGESTED).st_mode & 0o777, 0o600)
        self.assertIn(f"{NAME} | Testowski*", shown, "Testowski, Testowskiego, Testowskiej: one stem")
        self.assertNotIn("Pan ", shown, "a salutation is no part of a name")
        self.assertIn("Anna Kowalska", shown)
        self.assertFalse(terms.PERSONAL.exists())


class Issue19FormTests(_Base):
    """The forms that the text of the epic names (Mcpgate-de/maisecrets#19, part 2): `/maisecrets:term add Jan
    Kowalski` masks the full name and the surname, also `Kowalskis`, `jan.kowalski` and a file name in NFD, and a
    term inside a stored password never splits it. Jan Kowalski is the stand-in name of the epic."""

    def setUp(self):
        super().setUp()
        self.assertEqual(_prompt("/maisecrets:term add Jan Kowalski")["decision"], "block")
        self.assertEqual(_prompt("/maisecrets:term add Łucja Wiśniewska")["decision"], "block")

    def test_the_full_name_and_the_surname_in_its_forms(self):
        for text in ("Jan Kowalski", "Herr Kowalski schreibt", "Kowalskis Akte", "jan.kowalski@", "jan.kowalski",
                     "JAN KOWALSKI", "Kowalski, Jan", "Jan\nKowalski"):
            with self.subTest(text=text):
                out = _out(_bash(f"<{text}>"))
                self.assertNotIn("kowalsk", out.lower())
                self.assertRegex(out, REF_RE)
        self.assertEqual(_bash("Jan alone"), {}, "the first name alone stays visible")
        self.assertEqual(_bash("Kowalskiego"), {}, "the surname is a whole word, never a stem")

    def test_a_file_name_in_nfd(self):
        import unicodedata
        for text in ("łucja_wiśniewska.pdf", "Wiśniewska.docx", "Akte Wiśniewska"):
            nfd = unicodedata.normalize("NFD", text)
            self.assertNotEqual(nfd, text)
            with self.subTest(text=text):
                out = _out(_bash(f"/Users/x/Documents/{nfd}"))
                self.assertNotIn(unicodedata.normalize("NFD", "wiśniewsk"), out.lower())
                self.assertNotIn("wiśniewsk", unicodedata.normalize("NFC", out).lower())

    def test_a_term_inside_a_stored_password_never_splits_it(self):
        value = "Kowalski#Lato" + "2024"
        self.assertEqual(_prompt(f"password: {value}")["decision"], "block")
        secret = re.compile(re.escape(OPEN) + r"SECRET_c\d+" + re.escape(CLOSE))
        out = _out(_bash(f"the value is {value} ok"))
        self.assertNotIn("lato2024", out.lower())
        self.assertRegex(out, r"\Athe value is " + secret.pattern + r" ok\Z")


class EndToEndTests(_Base):
    """The path of a new user, through the real entry point (hooks/dispatch.py) in child processes with the temp
    home: one typed command, then the next tool result is masked."""

    def run_hook(self, event: str, payload: dict) -> dict:
        r = subprocess.run([sys.executable, str(ROOT / "hooks" / "dispatch.py"), event], input=json.dumps(payload),
                           capture_output=True, text=True, timeout=60, env=dict(os.environ))
        self.assertEqual(r.returncode, 0, r.stderr[-500:])
        return json.loads(r.stdout) if r.stdout.strip() else {}

    def test_one_typed_command_then_the_next_tool_output_is_masked(self):
        start = self.run_hook("session-start", {"hook_event_name": "SessionStart", "session_id": "E1", **CLAUDE})
        self.assertNoTerm(json.dumps(start), "the session start")
        added = self.run_hook("user-prompt", {"hook_event_name": "UserPromptSubmit", "session_id": "E1",
                                              "source": "user", "transcript_path": "", **CLAUDE,
                                              "prompt": f"/maisecrets:term add {NAME}"})
        self.assertEqual(added["decision"], "block")
        self.assertIn("is on your list now as NAME_1", added["reason"])
        result = self.run_hook("post-tool", {"hook_event_name": "PostToolUse", "tool_name": "Bash",
                                             "session_id": "E1", "transcript_path": "", **CLAUDE,
                                             "tool_input": {"command": "cat crm-export.txt"},
                                             "tool_response": {"stdout": f"Customer: {NAME}\n", "stderr": ""}})
        shown = result["hookSpecificOutput"]["updatedToolOutput"]["stdout"]
        self.assertRegex(shown, r"\ACustomer: " + REF_RE.pattern + r"\n\Z")
        self.assertIn("NAME_c", result["systemMessage"], "the person sees what was replaced")
        call = self.run_hook("pre-tool", {"hook_event_name": "PreToolUse", "tool_name": "Bash", "session_id": "E1",
                                          "transcript_path": "", **CLAUDE, "cwd": "/tmp",
                                          "tool_input": {"command": f"echo {REF_RE.search(shown).group()}"}})
        self.assertNotEqual(call.get("hookSpecificOutput", {}).get("permissionDecision"), "deny")
        self.assertNoTerm(json.dumps(call), "the tool call")


if __name__ == "__main__":
    unittest.main()
