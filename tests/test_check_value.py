"""ms:(…): the person checks whether maisecrets would catch a value, and the value never reaches the model
(maisecrets/check_value.py, hooks._check_value, README "Check a value first").

The rules under test: a prompt that starts with ms:( is always blocked, also without the closing bracket; the verdict is
the one the normal prompt path gives for the same value; the answer names types and rule ids and never the value; a
value no rule caught is stored as /maisecrets:put stores it, where storing is allowed and helps; the transcript loses
the prompt as typed. Synthetic values only; a placeholder is built from OPEN and CLOSE, so the file holds none.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one
Path(os.environ["MAISECRETS_HOME"]).mkdir(parents=True, exist_ok=True)
Path(os.environ["MAISECRETS_HOME"], "config.json").write_text('{"backend": "jsonfile", "allow_plaintext_store": true}')

from maisecrets import check_value, detect, hooks, incidents, notices, settings, terms, user_rules  # noqa: E402
from maisecrets.placeholder import CLOSE, OPEN  # noqa: E402
from maisecrets.vault import HOME, Vault  # noqa: E402
import _hygiene  # noqa: E402
from _hygiene import CLAUDE, CODEX  # noqa: E402

CONFIG = '{"backend": "jsonfile", "allow_plaintext_store": true}'
GLPAT = "glpat-" + "A1b2C3d4E5f6G7h8I9j0"          # a rule catches it (gitlab-pat)
ALLOWED = "glpat-" + "Q9w8E7r6T5y4U3i2O1p0"        # a rule would catch it; the allow list allows it
PASSWORD = "Wq7-" + "pLm2xZr9Tv"                   # no shape: caught only when the store holds it
UNSEEN = "Hv4-" + "kTr8mZq2Wx"                     # no shape and not stored: not caught
MAIL = "jane.roe" + "@probe-mail.de"               # a rule catches it; `rule: email` switches the rule off
NAME = "Zbigniew " + "Testowski"                   # a term
PHRASE = "Tr0ub4dor& " + "7horses! b4tt3ry"         # a passphrase: each word has a letter and a digit or a sign
# ordinary text that no rule catches and that a check must not store: two words, prose, prose with a number, a digest
# with its file, a UUID, a version pin, a command line, a name, a sentence of East Asia, a vendor's example key
ORDINARY_TEXTS = ("Apfel Birne", "correct horse battery staple", "Call me at 5 tomorrow!",
                  "e3b0c44298fc1c14" + "9afbf4c8996fb924  file.txt", "3f2504e0-4f89-11d3-" + "9a0c-0305e82c3301",
                  "passlib>=1.7,<2", "git log --oneline -n 20", "Wartungsfenster", "密码：至少8位（含1个大写字母）",
                  "wJalrXUtnFEMI/K7MDENG/" + "bPxRfiCYEXAMPLEKEY", "release-notes-2026:", "npm-github:",
                  "2026-10-17T12:30:00Z", "v1.2.3-rc.4", "ai-gateway#1191", "IMG_20261017_123045.jpg",
                  "0x7ffe" + "efbff5c8", "DB_HOST=db1.local", "keyring~=24.3", "Tr0ub4dor& horse battery",
                  "e-mail, x-ray, t-shirt", "db=prod123!", "--x=value123!", "V1.2.3-rc.4", "version-1.2.3")
STATE = ("index.json", "vault.json", "audit.log", "hooks.log", "events.log", "terms.txt", "terms.marked.json",
         ".terms-state", ".terms-cache", "allow.txt", "hints.json")
# the files that hold a value by design: the plaintext test store, the term list and the allow list
HOLD_VALUES = ("vault.json", "terms.txt", "terms.marked.json", ".terms-cache", "allow.txt")


def _says(type_: str) -> str:
    """What a verdict names for a hit of this type: its noun and the placeholder type the AI sees, never a rule id."""
    return f"{notices.type_word(type_)} ({OPEN}{type_}_…{CLOSE})"


def _clean() -> None:
    for f in STATE:
        Path(HOME, f).unlink(missing_ok=True)
    shutil.rmtree(Path(HOME, "pending"), ignore_errors=True)
    Path(HOME, "config.json").write_text(CONFIG)
    incidents.clear(Path(HOME))
    hooks._live_cache.clear()
    detect.reset_rules()


def setUpModule():  # noqa: N802 - unittest hook
    _clean()


def tearDownModule():  # noqa: N802 - unittest hook
    _clean()
    _hygiene.assert_pristine()


def _prompt(prompt: str, client=CLAUDE, session: str = "S1", **extra) -> dict:
    hooks._live_cache.clear()
    payload = {"hook_event_name": "UserPromptSubmit", "prompt": prompt, "session_id": session, "transcript_path": "",
               "source": "user", **client, **extra}
    if client is CODEX:
        del payload["source"]          # Codex sends none
    return hooks.user_prompt(payload)


def _hits() -> list:
    """(type, rule) of the last detection the events log records: what the prompt path took out."""
    try:
        lines = Path(HOME, "events.log").read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return []
    events = [json.loads(x) for x in lines if '"hits"' in x]
    return sorted((h["type"], h["kind"]) for h in events[-1]["hits"]) if events else []


def _home_text() -> str:
    parts = []
    for p in Path(HOME).rglob("*"):
        if p.is_file() and p.name not in HOLD_VALUES:
            parts.append(p.read_bytes().decode("utf-8", errors="replace"))
    return "\n".join(parts)


class _Base(unittest.TestCase):
    def setUp(self):
        _clean()
        self.addCleanup(_clean)
        self.copied = []
        _hygiene.patch(self, hooks, "_clipboard", lambda t: self.copied.append(t) or True)
        self.scrubs = []
        _hygiene.patch(self, hooks, "_scrub_transcript_later",
                       lambda path, values, refs, seconds=15.0, session=None, hidden=False:
                       self.scrubs.append(list(values)))


class ParseTests(unittest.TestCase):
    def test_only_a_prompt_that_starts_with_ms_bracket_is_a_check(self):
        for p in ("ms:(x)", "  ms:(x)", "\n\tms:(x", "Ms:(x)", "MS:(x)", "ms:()", "ms:(", "ms: (x)", "ms : ( x",
                  "ms\uff1a\uff08x\uff09", "ms:\uff08x"):
            self.assertIsNotNone(check_value.parse(p), p)
        for p in ("ms:", "ms: x", "ms: see (x)", "ms (x)", "ms(x)", "see ms:(x)", "#ms:(x)", "ms:[x]", "/ms:(x)", "",
                  None, 3):
            self.assertIsNone(check_value.parse(p), p)

    def test_every_blank_the_mod_takes_is_taken_here_too(self):
        # the blanks of JavaScript's \s (claude-mod/maisecrets-mod.mjs CHECK): the mod passes such a prompt on as a
        # check, so the hook must block it as one
        js_blanks = "\t\n\v\f\r \u00a0\u1680" + "".join(map(chr, range(0x2000, 0x200B))) + \
            "\u2028\u2029\u202f\u205f\u3000\ufeff"
        for ch in js_blanks + "\u200b\u200c\u200d\u2060":
            self.assertEqual(check_value.parse(ch + "ms:(x)"), "x", hex(ord(ch)))

    def test_the_value_ends_at_the_last_bracket_or_at_the_end(self):
        self.assertEqual(check_value.parse("ms:(a)b)"), "a)b")
        self.assertEqual(check_value.parse("ms:(pa(ss)"), "pa(ss")
        self.assertEqual(check_value.parse("ms:(abc"), "abc")
        self.assertEqual(check_value.parse("ms:(abc) and more"), "abc")
        self.assertEqual(check_value.parse("ms\uff1a\uff08abc\uff09"), "abc")

    def test_one_blank_at_most_goes_on_each_side(self):
        self.assertEqual(check_value.parse("ms:( abc )"), "abc")
        self.assertEqual(check_value.parse("ms:(  abc  )"), " abc ")
        self.assertEqual(check_value.parse("ms:(abc "), "abc")

    def test_several_groups_are_parsed_one_by_one(self):
        self.assertEqual(check_value.parse_all("ms:(A B) ms:(x)"), [("A B", True), ("x", True)])
        self.assertEqual(check_value.parse_all("ms:(a)\nMS:( b )  ms:(c"), [("a", True), ("b", True), ("c", True)])
        # without a `)` before it, the next group still ends the one before: no value holds `ms:(`
        self.assertEqual(check_value.parse_all("ms:(a b ms:(c)"), [("a b", True), ("c", True)])
        # a `)` inside a value works in every group; the last group ends at its last `)`
        self.assertEqual(check_value.parse_all("ms:(pa)ss) ms:(x)y) and more"), [("pa)ss", True), ("x)y", True)])
        self.assertEqual(check_value.parse_all("ms:(a)b)"), [("a)b", True)])
        # a later group stores only when the first one may (a near form at the start stores nothing)
        self.assertEqual(check_value.parse_all("ms: (a) ms:(b)"), [("a", False), ("b", False)])
        # the text after the last `)` of a group is no part of it, as after the last group
        self.assertEqual(check_value.parse_all("ms:(a1) und ms:(b2)"), [("a1", True), ("b2", True)])
        # a near form starts a new group too
        self.assertEqual(check_value.parse_all("ms:(a) ms: (b) MS\uff1a\uff08c"), [("a", True), ("b", True),
                                                                                   ("c", True)])
        # a `)` glued to the next `ms:(` ends the group too
        self.assertEqual(check_value.parse_all("ms:(a)ms:(b)"), [("a", True), ("b", True)])
        # `ms:(` glued to a word is no new group
        self.assertEqual(check_value.parse_all("ms:(xms:(y)"), [("xms:(y", True)])
        self.assertEqual(check_value.parse("ms:(A B) ms:(x)"), "A B")

    def test_a_key_on_its_own_lines_keeps_its_lines(self):
        key = "-----BEGIN " + "KEY-----\nAAAA\nBBBB\n-----END " + "KEY-----"
        self.assertEqual(check_value.parse(f"ms:(\n{key}\n)"), key)
        self.assertEqual(check_value.parse(f"ms:(\r\n{key}\r\n)"), key)
        self.assertEqual(check_value.parse(f"ms:(\n{key}\n"), key)


class AlwaysBlockedTests(_Base):
    def test_every_check_is_blocked_with_and_without_the_closing_bracket(self):
        Vault().put(PASSWORD, "SECRET", "manual")
        for value in (GLPAT, PASSWORD, UNSEEN, "hello world", "", MAIL):
            for prompt in (f"ms:({value})", f"ms:({value}", f"  Ms:( {value} "):
                for client in (CLAUDE, CODEX):
                    with self.subTest(prompt=prompt[:7], client=client):
                        out = _prompt(prompt, client=client)
                        self.assertEqual(out.get("decision"), "block")
                        if client is CLAUDE:
                            self.assertTrue(out["hookSpecificOutput"]["suppressOriginalPrompt"])
                        self.assertIn("This prompt was not sent", out["reason"])

    def test_a_check_from_a_program_or_a_subagent_is_blocked_too(self):
        for extra in ({"source": "scheduled"}, {"agent_id": "a1"}):
            out = _prompt(f"ms:({UNSEEN})", **extra)
            self.assertEqual(out["decision"], "block")
            self.assertIn("It was not stored", out["reason"])
            self.assertFalse(Path(HOME, "vault.json").exists() and UNSEEN in Path(HOME, "vault.json").read_text())

    def test_the_mod_gets_a_drop_with_the_verdict_and_never_a_text(self):
        for prompt, said in ((f"ms:({GLPAT})", _says("SECRET")), (f"ms:({GLPAT}", _says("SECRET")),
                             (f" ms:( {UNSEEN} )", "maisecrets stored it as")):
            out = hooks.rewrite_prompt({"prompt": prompt, "session_id": "S1", "origin": "composer"})
            self.assertEqual(sorted(out), ["drop"], "a check is never rewritten")
            self.assertIn(said, out["drop"])
            self.assertNotIn(GLPAT, out["drop"])
            self.assertNotIn(UNSEEN, out["drop"])
        self.assertTrue(any(s[0] == f" ms:( {UNSEEN} )" for s in self.scrubs), "the transcript scrub starts")

    def test_a_check_through_the_mod_from_a_program_stores_nothing(self):
        out = hooks.rewrite_prompt({"prompt": f"ms:({UNSEEN})", "session_id": "S1", "origin": "sdk"})
        self.assertIn("It was not stored", out["drop"])
        self.assertFalse(Path(HOME, "index.json").exists())

    def test_a_near_form_is_blocked_but_stores_nothing(self):
        for prompt in (f"ms: ({UNSEEN})", f"MS : ( {UNSEEN} ) and more", f"ms\uff1a\uff08{UNSEEN}\uff09"):
            out = _prompt(prompt)
            self.assertEqual(out["decision"], "block")
            self.assertIn("does not start with ms:( exactly", out["reason"])
        self.assertFalse(Path(HOME, "index.json").exists())

    def test_a_check_saves_no_pending_prompt_and_copies_nothing(self):
        _prompt(f"ms:({GLPAT})")
        _prompt(f"ms:({UNSEEN})")
        self.assertFalse(Path(HOME, "pending").exists(), "/maisecrets:send must have nothing of a check to send")
        self.assertEqual(self.copied, [])


class SameVerdictTests(_Base):
    """For each kind of value, ms:(v) gives the verdict that the normal prompt v gives: caught or not, with the same
    types and rules. Each side runs from the same state of the store, the terms and the allow list."""

    CASES = {
        "a rule": (GLPAT, None),
        "a stored value only": (PASSWORD, "store"),
        "a term": (NAME, "term"),
        "allowed by the allow list (a value)": (ALLOWED, "allow-value"),
        "allowed by the allow list (a rule)": (MAIL, "allow-rule"),
        "not caught": (UNSEEN, None),
    }

    def _arrange(self, how) -> None:
        _clean()
        if how == "store":
            Vault().put(PASSWORD, "SECRET", "manual", session="S0")
        elif how == "term":
            terms.PERSONAL.write_text(f"PERSON_A  {NAME}\n", encoding="utf-8")
            os.chmod(terms.PERSONAL, 0o600)
        elif how == "allow-value":
            user_rules.ALLOW_FILE.write_text(ALLOWED + "\n", encoding="utf-8")
        elif how == "allow-rule":
            user_rules.ALLOW_FILE.write_text("rule: email\n", encoding="utf-8")
        detect.reset_rules()
        hooks._live_cache.clear()

    def test_ms_and_the_normal_prompt_give_the_same_verdict(self):
        seen = set()
        for name, (value, how) in self.CASES.items():
            with self.subTest(name):
                self._arrange(how)
                normal = _prompt(value)
                normal_caught = normal.get("decision") == "block"
                normal_hits = _hits() if normal_caught else []
                self._arrange(how)
                check = _prompt(f"ms:({value})")
                self.assertEqual(check["decision"], "block")
                check_caught = check["reason"].startswith("✓ maisecrets masks")
                self.assertEqual(check_caught, normal_caught)
                self.assertEqual(check["reason"].startswith(check_value.NOT_CAUGHT), not normal_caught)
                self.assertEqual(_hits() if check_caught else [], normal_hits)
                for type_, kind in normal_hits:
                    self.assertIn(_says(type_), check["reason"])
                seen.add(normal_caught)
        self.assertEqual(seen, {True, False}, "the cases cover both verdicts")

    def test_the_allow_list_is_named_and_nothing_is_stored(self):
        for value, how, why in ((ALLOWED, "allow-value", "allows this exact value"),
                                (MAIL, "allow-rule", "switches off the rule email")):
            self._arrange(how)
            out = _prompt(f"ms:({value})")
            self.assertIn(why, out["reason"])
            self.assertIn("It was not stored", out["reason"])
            self.assertFalse(Path(HOME, "index.json").exists())

    def test_several_hits_are_all_named(self):
        out = _prompt(f"ms:({GLPAT} {MAIL})")
        self.assertIn("masks 2 parts of this", out["reason"])
        self.assertIn(_says("SECRET"), out["reason"])
        self.assertIn(_says("EMAIL"), out["reason"])
        self.assertNotIn("gitlab-pat", out["reason"], "no rule id")

    def test_each_group_gives_the_verdict_of_its_own_normal_prompt(self):
        # ms:(v) ms:(w): each line is the verdict that the normal prompt v (and w) gives alone, from the same state
        others = (GLPAT, "Apfel Birne")
        for name, (value, how) in self.CASES.items():
            for other in others:
                if other == value:
                    continue
                for first in (True, False):
                    with self.subTest(name, other=other[:5], first=first):
                        self._arrange(how)
                        normal = _prompt(value).get("decision") == "block"
                        normal_hits = _hits() if normal else []
                        self._arrange(how)
                        prompt = f"ms:({value}) ms:({other})" if first else f"ms:({other}) ms:({value})"
                        out = _prompt(prompt)
                        self.assertEqual(out["decision"], "block")
                        lines = out["reason"].split("\n\n")[0].split("\n")
                        self.assertEqual(len(lines), 2, out["reason"])
                        line = lines[0 if first else 1]
                        self.assertTrue(line.startswith(f"Value {1 if first else 2}: "), line)
                        self.assertEqual("✓ maisecrets masks" in line, normal, line)
                        for type_, kind in normal_hits:
                            self.assertIn(_says(type_), line)
                        other_line = lines[1 if first else 0]
                        self.assertEqual(_says("SECRET") in other_line, other == GLPAT, other_line)
                        if other == GLPAT and "SECRET" not in {type_ for type_, _kind in normal_hits}:
                            self.assertNotIn(_says("SECRET"), line, "the hit of the other group stays in its line")
                        self.assertTrue(out["reason"].endswith(check_value.NOT_SENT))

    def test_a_group_does_not_see_what_a_group_before_it_stored(self):
        # the same unseen value twice: both lines say what the normal prompt says, and it is stored once
        out = _prompt(f"ms:({UNSEEN}) ms:({UNSEEN})")
        lines = out["reason"].split("\n\n")[0].split("\n")
        self.assertEqual([x.split(": ", 1)[1] for x in lines][0], [x.split(": ", 1)[1] for x in lines][1])
        self.assertIn("maisecrets stored it as", lines[1])
        # a later group that holds the value of an earlier one: its verdict comes from the state before the prompt
        _clean()
        out = _prompt(f"ms:({UNSEEN}) ms:(see {UNSEEN} here)")
        self.assertNotIn("stored value", out["reason"])
        self.assertEqual(len(json.loads(Path(HOME, "index.json").read_text())["entries"]), 1)

    def test_random_letters_that_a_check_stores_are_scrubbed_alone(self):
        letters = "qzmxnplkjh" + "gfdsavwbyc"
        self.assertIn(letters, check_value.scrub_forms(f"ms:({letters}) ms:(x)", [letters, "x"]))
        self.assertNotIn("permissionMode", check_value.scrub_forms("ms:(permissionMode)", ["permissionMode"]))

    def test_a_failed_check_with_several_groups_loses_each_value(self):
        prompt = f"ms:( {UNSEEN}) ms:({PASSWORD}"
        with tempfile.TemporaryDirectory() as d:
            t = Path(d, "t.jsonl")
            t.write_text(json.dumps({"type": "user", "message": {"content": PASSWORD}}) + "\n", encoding="utf-8")
            hooks._scrub_failed_prompt_now(prompt, str(t))
            self.assertNotIn(PASSWORD, t.read_text(encoding="utf-8"), "the value of the second group alone")

    def test_the_text_ms_bracket_is_never_a_hit(self):
        # the live finding: `ms:(A B) ms:(x)` read "A B) ms:(x" as one value; now each group is its own value
        out = _prompt("ms:(Apfel Birne) ms:(x)")
        self.assertEqual(out["reason"].count(check_value.NOT_CAUGHT), 2, out["reason"])
        self.assertNotIn("✓", out["reason"])
        self.assertEqual(_hits(), [])
        self.assertFalse(Path(HOME, "index.json").exists(), "nothing is stored")

    def test_the_mod_gets_one_drop_with_every_verdict(self):
        out = hooks.rewrite_prompt({"prompt": f"ms:({GLPAT}) ms:({UNSEEN})", "session_id": "S1", "origin": "composer"})
        self.assertEqual(sorted(out), ["drop"])
        self.assertIn("Value 1: ✓ maisecrets masks this as " + _says("SECRET"), out["drop"])
        self.assertIn("Value 2: " + check_value.NOT_CAUGHT + " maisecrets stored it as", out["drop"])
        self.assertNotIn(GLPAT, out["drop"])
        self.assertNotIn(UNSEEN, out["drop"])
        # the scrub takes each value alone, not only the prompt as typed: a later record can hold the value alone
        self.assertTrue(any(UNSEEN in scrub and GLPAT in scrub for scrub in self.scrubs), self.scrubs and "each value")

    def test_a_private_key_over_several_lines_is_caught_whole(self):
        body = "\n".join("MIIEowIBAAKCAQEA" + c * 48 for c in "xyzw")
        key = "-----BEGIN " + "RSA PRIVATE KEY-----\n" + body + "\n-----END " + "RSA PRIVATE KEY-----"
        normal = _prompt(key)
        self.assertEqual(normal["decision"], "block")
        hits = _hits()
        _clean()
        out = _prompt(f"ms:(\n{key}\n)")
        self.assertTrue(out["reason"].startswith("✓"), out["reason"])
        self.assertEqual(_hits(), hits)


class NeverTheValueTests(_Base):
    def test_no_answer_and_no_file_but_the_store_holds_the_value(self):
        Vault().put(PASSWORD, "SECRET", "manual")
        hooks._live_cache.clear()
        for value in (GLPAT, PASSWORD, UNSEEN, MAIL, NAME, "zz-short", "two words here"):
            for client in (CLAUDE, CODEX):
                out = _prompt(f"ms:({value})", client=client)
                self.assertNotIn(value, json.dumps(out, ensure_ascii=False))
                self.assertNotIn(value, _home_text())
        for scrub in self.scrubs:
            self.assertTrue(any(s.startswith("ms:(") for s in scrub), "the scrub takes the prompt as typed")

    def test_the_transcript_loses_the_prompt_as_typed(self):
        for prompt in (f"ms:({GLPAT})", f"ms:( {UNSEEN}", "ms:(\npassword: " + PASSWORD + "z\nline two\n)"):
            with tempfile.TemporaryDirectory() as d:
                t = Path(d, "t.jsonl")
                t.write_text(json.dumps({"type": "user", "message": {"content": prompt}}) + "\n", encoding="utf-8")
                hooks._live_cache.clear()
                hooks.user_prompt({"prompt": prompt, "session_id": "S1", "transcript_path": str(t), "source": "user",
                                   **CLAUDE})
                text = t.read_text(encoding="utf-8")
                for value in (GLPAT, UNSEEN, PASSWORD):
                    self.assertNotIn(value, text)
                self.assertNotIn(json.dumps(prompt)[1:-1], text)
                json.loads(text)            # the record stays valid JSON

    def test_a_failed_check_still_loses_the_prompt_as_typed(self):
        # the hook could not finish (a damaged index, a config error, the watchdog): the scrub of the failure path
        # masks the check's prompt, which the detector alone does not find (Gate A and Gate B, round 1)
        prompt = f"ms:( {UNSEEN}"
        with tempfile.TemporaryDirectory() as d:
            t = Path(d, "t.jsonl")
            t.write_text(json.dumps({"type": "user", "message": {"content": prompt}}) + "\n", encoding="utf-8")
            hooks._scrub_failed_prompt_now(prompt, str(t))
            self.assertNotIn(UNSEEN, t.read_text(encoding="utf-8"))

    def test_a_failed_check_starts_the_late_scrub_before_the_detector(self):
        # the record comes after the hook; a detector that outlasts the child must not stop the late scrub
        prompt = f"ms:( {UNSEEN}"

        class Killed(BaseException):
            """the child's alarm ends the process in the middle of the scan: nothing after it runs"""

        def slow(*_a, **_k):
            raise Killed()
        _hygiene.patch(self, hooks.detect, "scan", slow)
        with self.assertRaises(Killed):
            hooks._scrub_failed_prompt_now(prompt, "/nonexistent/t.jsonl")
        self.assertTrue(any(prompt in s for s in self.scrubs), self.scrubs)

    def test_a_check_of_a_word_keeps_the_transcript_whole(self):
        # a value such as `true` or `content` is masked as the prompt that holds it, never in every record
        with tempfile.TemporaryDirectory() as d:
            t = Path(d, "t.jsonl")
            for word in ("true", "content", "message", "permissionMode"):
                prompt = f"ms:({word})"
                rec = {"type": "user", "isMeta": True, "message": {"role": "user", "content": prompt},
                       "permissionMode": "default"}
                t.write_text(json.dumps(rec) + "\n", encoding="utf-8")
                hooks._live_cache.clear()
                hooks.user_prompt({"prompt": prompt, "session_id": "S1", "transcript_path": str(t), "source": "user",
                                   **CLAUDE})
                got = json.loads(t.read_text(encoding="utf-8"))
                self.assertEqual(sorted(got), sorted(rec), word)
                self.assertTrue(got["isMeta"], word)
                self.assertNotIn(prompt, got["message"]["content"])

    def test_the_scrub_setting_off_starts_no_scrub(self):
        Path(HOME, "config.json").write_text(CONFIG[:-1] + ', "scrub_transcript": false}')
        _prompt(f"ms:({GLPAT})")
        self.assertEqual(self.scrubs, [])


class StoreTests(_Base):
    def test_a_value_no_rule_caught_is_stored_and_caught_from_then_on(self):
        out = _prompt(f"ms:({UNSEEN})")
        self.assertIn("maisecrets stored it as " + OPEN + "SECRET_c1" + CLOSE + ". For 1 day after each use it is "
                      "masked wherever it stands as a word of its own.", out["reason"])
        self.assertNotIn("From now on", out["reason"], "the store keeps it for its lifetime, not for good")
        self.assertEqual(Vault().get("SECRET_c1", session="S1"), (UNSEEN, "ok"))
        meta = json.loads(Path(HOME, "index.json").read_text())["entries"]["SECRET_c1"]
        self.assertEqual((meta["type"], meta["kind"]), ("SECRET", "manual"), "as /maisecrets:put stores it")
        self.assertEqual(_prompt(f"please use {UNSEEN} here")["decision"], "block")
        again = _prompt(f"ms:({UNSEEN})")
        self.assertIn("This value is already stored as " + OPEN + "SECRET_c1" + CLOSE, again["reason"])

    def test_a_passphrase_with_spaces_is_stored_and_the_answer_says_where_it_is_found(self):
        out = _prompt(f"ms:({PHRASE})")
        self.assertIn("maisecrets stored it as", out["reason"])
        self.assertIn("Inside a sentence it is not found", out["reason"])
        self.assertEqual(_prompt(PHRASE)["decision"], "block")

    def test_ordinary_text_is_not_stored(self):
        # a check of ordinary words stored them, and every later prompt with them was blocked (live finding, 0.6.32)
        want = (check_value.NOT_CAUGHT + " It looks like ordinary text, so it was not stored. If it is a secret, store "
                "it with /maisecrets:put.\n\n" + check_value.NOT_SENT)
        for text in ORDINARY_TEXTS:
            with self.subTest(text[:12]):
                self.assertEqual(_prompt(f"ms:({text})")["reason"], want)
                self.assertEqual(_prompt(text).get("decision"), None, "the normal prompt still goes out")
        self.assertFalse(Path(HOME, "index.json").exists())

    def test_a_credential_without_a_shape_is_still_stored(self):
        # signs that code uses too ($ = < > ...) and letters only at random are credentials (Gate A and Gate B, round 1)
        for value in (UNSEEN, PASSWORD, "Sommer" + "2026!x", "K7#mQ2" + "vL9pZ", "aB3$kL9" + "!mQ2z",
                      "Kx7=pLm2" + "#zR9", "q<Vx7Lm" + "9Kp3", "qzmxnplkjh" + "gfdsavwbyc", "x9!Lq 7#mZ " + "4$kP",
                      "Sommer2026" + "#1", "Hamburg" + "#2026", "Kq9>4mPq" + "!zLx", "Zq>=7mP" + "!2"):
            with self.subTest(value[:3]):
                self.assertTrue(check_value.looks_like_a_credential(value), value[:3])
        self.assertIn("maisecrets stored it as", _prompt(f"ms:({PASSWORD})")["reason"])

    def test_storing_is_refused_where_it_is_not_allowed_or_would_not_help(self):
        for prompt, why in ((f"ms:({UNSEEN[:6]})", "only from 8 characters"), ("ms:(Apfel)", "only from 8 characters"),
                            (f"ms:({UNSEEN}\n{UNSEEN})", "more than one line")):
            out = _prompt(prompt)
            self.assertIn(why, out["reason"])
            self.assertIn("so it was not stored", out["reason"])
        self.assertFalse(Path(HOME, "index.json").exists())

    def test_a_placeholder_next_to_a_value_does_not_hide_the_verdict(self):
        out = _prompt("ms:(" + OPEN + "SECRET_c9" + CLOSE + f" {GLPAT})")
        self.assertIn(_says("SECRET"), out["reason"])
        out = _prompt("ms:(" + OPEN + "SECRET_c9" + CLOSE + f" {UNSEEN})")
        self.assertIn("It holds a maisecrets placeholder, so it was not stored", out["reason"])

    def test_an_empty_check_and_a_placeholder_store_nothing(self):
        self.assertIn("put the value between the brackets", _prompt("ms:()")["reason"])
        self.assertIn("this is a maisecrets placeholder", _prompt("ms:(" + OPEN + "SECRET_c9" + CLOSE + ")")["reason"])
        self.assertFalse(Path(HOME, "index.json").exists())


class TipTests(_Base):
    def test_claude_code_names_the_check_once_under_a_blocked_prompt(self):
        first = _prompt(f"check {GLPAT} in CI")
        self.assertIn(check_value.TIP_CLAUDE, first["reason"])
        second = _prompt(f"check {GLPAT} in CI")
        self.assertNotIn(check_value.TIP_CLAUDE, second["reason"])
        ok, _ = settings.apply_typed("hints", "reset")
        self.assertTrue(ok)
        self.assertIn(check_value.TIP_CLAUDE, _prompt(f"check {GLPAT} in CI")["reason"])

    def test_the_mod_gets_the_tip_once(self):
        first = hooks.rewrite_prompt({"prompt": f"check {GLPAT} in CI", "session_id": "S1"})
        self.assertEqual(first.get("tip"), check_value.TIP_CLAUDE)
        self.assertNotIn("tip", hooks.rewrite_prompt({"prompt": f"check {GLPAT} in CI", "session_id": "S1"}))

    def test_codex_gets_no_tip_in_its_block_notice(self):
        out = _prompt(f"check {GLPAT} in CI", client=CODEX)
        self.assertNotIn("ms:(", out["reason"])

    def test_tips_off_gives_no_tip(self):
        Path(HOME, "config.json").write_text(CONFIG[:-1] + ', "tips": false}')
        self.assertNotIn("ms:(", _prompt(f"check {GLPAT} in CI")["reason"])

    def test_the_settings_list_names_the_hint(self):
        self.assertIn("Check a value with ms:(…) · not shown yet", "\n".join(settings._hint_lines()))
        _prompt(f"check {GLPAT} in CI")
        self.assertIn("Check a value with ms:(…) · shown", "\n".join(settings._hint_lines()))

    @unittest.skipIf(os.name == "nt", "run.sh: the session start of a POSIX launcher")
    def test_codex_names_the_check_once_at_the_session_start(self):
        with tempfile.TemporaryDirectory() as d:
            home = Path(d)
            (home / "store").mkdir()
            (home / "store" / "config.json").write_text(CONFIG)
            env = {k: v for k, v in os.environ.items() if not k.startswith(("CLAUDE", "CODEX_"))}
            env.update({"HOME": str(home), "MAISECRETS_" + "HOME": str(home / "store"), "PYTHONDONTWRITEBYTECODE": "1"})
            payload = {"session_id": "S2", "source": "startup", "hook_event_name": "SessionStart",
                       "transcript_path": str(home / ".codex" / "sessions" / "r.jsonl")}

            def start() -> str:
                r = subprocess.run(["bash", str(ROOT / "hooks" / "run.sh"), "session-start"],
                                   input=json.dumps(payload), capture_output=True, text=True, env=env, timeout=60)
                self.assertEqual(r.returncode, 0, r.stderr)
                return json.loads(r.stdout).get("systemMessage", "")
            # the first start names ms:(…) in its try-it line; the Codex tip would say it twice, and its hint is used
            first = start()
            self.assertIn("Try it: send ms:(", first)
            self.assertNotIn(check_value.TIP_CODEX, first)
            self.assertIn("check_value", (home / "store" / "hints.json").read_text())
            self.assertNotIn(check_value.TIP_CODEX, start())
            payload["transcript_path"] = str(home / ".claude" / "projects" / "p" / "r.jsonl")
            (home / "store" / "hints.json").unlink()
            self.assertNotIn(check_value.TIP_CLAUDE, start(), "Claude Code names it under a blocked prompt")



class FormatReportTests(unittest.TestCase):
    """ms:(…) on a value no rule caught offers to report its format: the shape, never the value."""

    def test_the_shape_names_the_fixed_start_only_before_a_random_rest(self):
        tok = "sb" + "_pat_" + "Qx7Lm2Np9Rt4Vb8Kc3Zd6Hf1Jg5Ws0Ye"
        self.assertEqual(check_value.format_shape(tok),
                         {"prefix": "sb_pat_", "length": 32, "kinds": ["small letters", "capitals", "digits"],
                          "signs": "", "pattern": "sb_pat_[A-Za-z0-9]{32}"})
        # a password with a word before an underscore keeps its start: the rest is too short to be a token body
        self.assertEqual(check_value.format_shape("summer_" + "rain42!")["prefix"], "")

    def test_the_report_line_holds_the_shape_and_never_the_value(self):
        tok = "sb" + "_pat_" + "Qx7Lm2Np9Rt4Vb8Kc3Zd6Hf1Jg5Ws0Ye"
        line = check_value.format_report(tok)
        self.assertIn("sb_pat_", line)
        self.assertIn("32 characters", line)
        self.assertIn("github.com/", line)
        self.assertNotIn(tok[7:], line)
        self.assertNotIn(tok[7:].replace("", "%")[1:4], line)   # nor a percent-encoded piece of it

    def test_the_link_stands_on_a_line_of_its_own_and_fits_one_terminal_line(self):
        # a link of 600 characters wrapped, and its indented second line could not be copied whole (2026-10-23)
        tok = "sb" + "_pat_" + "Qx7Lm2Np9Rt4Vb8Kc3Zd6Hf1Jg5Ws0Ye"
        links = [ln for ln in check_value.format_report(tok).split("\n") if "github.com" in ln]
        self.assertEqual(len(links), 1)
        self.assertTrue(links[0].startswith("https://github.com/"), "the link starts its line")
        self.assertLessEqual(len(links[0]), 130)
        self.assertIn("template=format.yml", links[0])
        template = Path(__file__).resolve().parent.parent / ".github" / "ISSUE_TEMPLATE" / check_value.FORMAT_TEMPLATE
        self.assertTrue(template.is_file(), "the template the link names exists")

    def test_no_link_for_a_value_without_a_fixed_start(self):
        # no format rule can follow from a shape without a prefix: a report would be an issue nobody can act on
        for value in ("abcdefg" + "_hij12k", "Hv4-" + "kTr8mZq2Wx", "x" * 4 + "7Gq2Lm9Zr4Tb8Wc1"):
            with self.subTest(value=value[:4]):
                self.assertEqual(check_value.format_report(value), "")

    def test_no_line_when_reporting_is_off(self):
        from unittest import mock
        from maisecrets import events
        with mock.patch.object(events, "tracker", return_value=None):
            self.assertEqual(check_value.format_report("sb" + "_pat_" + "Qx7Lm2Np9Rt4Vb8Kc3Zd6Hf1"), "")

    def test_a_stored_value_gets_the_report_line_only_with_a_fixed_start(self):
        self.assertNotIn("Unknown format?", _prompt(f"ms:({UNSEEN})")["reason"])
        prefixed = "zq" + "x_" + "Qx7Lm2Np9Rt4Vb8Kc3Zd6Hf1"
        out = _prompt(f"ms:({prefixed})")
        self.assertIn("Unknown format? Report its shape", out["reason"])
        self.assertNotIn(prefixed[4:], out["reason"].split("Report its shape", 1)[1])


class VerdictModelTests(_Base):
    """The verdict says what a value is masked as (a noun and the placeholder type) and how sure that is (the form of
    the rule or the source of the hit), and never a rule id (maisecrets/verdict.py)."""

    LABELLED = "Zq8-" + "synthetic-pw"        # no shape: found only by the label in front of it

    def test_a_format_hit_says_it_is_masked_also_alone(self):
        out = _prompt(f"ms:({GLPAT})")["reason"]
        self.assertTrue(out.startswith("✓ maisecrets masks this as a secret (" + OPEN + "SECRET_…" + CLOSE + ")."), out)
        self.assertIn("maisecrets knows this format, so it masks it wherever it appears, also alone.", out)
        self.assertNotIn("gitlab-pat", out)

    def test_a_label_hit_names_the_label_and_says_how_long_the_value_is_stored(self):
        out = _prompt(f"ms:(password: {self.LABELLED})")["reason"]
        self.assertIn("found it by the label in front of it (`password:`). A value like this without such a label is "
                      "not found.", out)
        self.assertIn("This value is now stored, so it is masked wherever it appears for 1 day (each use extends it).",
                      out)
        self.assertNotIn("ds-keyword", out)
        self.assertNotIn(self.LABELLED, out)
        self.assertEqual(_prompt(f"see {self.LABELLED} here")["decision"], "block", "the stored half is true")

    def test_a_short_label_hit_is_not_promised_to_be_found_again(self):
        out = _prompt("ms:(password: Zq8-x" + "y)")["reason"]
        self.assertIn("It is too short to be found again without the label.", out)
        self.assertNotIn("now stored", out)

    def test_a_default_word_after_a_label_is_not_promised_to_be_found_again(self):
        out = _prompt("ms:(password: postgres)")["reason"]
        self.assertIn("It is a common word, so it is found again only with the label.", out)
        self.assertNotIn("now stored", out)

    def test_several_hits_get_one_line_each_in_text_order(self):
        out = _prompt(f"ms:(password: {self.LABELLED} mail {MAIL})")["reason"].split("\n\n")[0]
        lines = out.split("\n")
        self.assertEqual(lines[0], "✓ maisecrets masks 2 parts of this:")
        self.assertTrue(lines[1].startswith("  · " + _says("SECRET") + ", found by the label in front of it "
                                            "(`password:`)"), lines[1])
        self.assertEqual(lines[2], "  · " + _says("EMAIL") + ", maisecrets knows this format and masks it everywhere")

    def test_the_same_line_twice_is_said_once(self):
        other = "glpat-" + "Z9y8X7w6V5u4T3s2R1q0"
        out = _prompt(f"ms:({GLPAT} {other})")["reason"].split("\n\n")[0]
        self.assertEqual(out.split("\n")[1:], ["  · 2 × " + _says("SECRET") + ", maisecrets knows this format and "
                                                "masks it everywhere"])

    def test_the_allow_list_is_named_with_its_file(self):
        Path(user_rules.ALLOW_FILE).write_text(ALLOWED + "\n", encoding="utf-8")
        detect.reset_rules()
        out = _prompt(f"ms:({ALLOWED})")["reason"]
        self.assertIn("Your allow list lets it through: it allows this exact value.", out)
        self.assertIn(f"remove that line from {user_rules.ALLOW_FILE}.", out)


if __name__ == "__main__":
    unittest.main()
