"""A reserved word of a language as the value after a secret label (Mcpgate-de/maisecrets#29).

`const secret = readonly;` gave a SECRET hit, and the vault masked the word in every later file. The rules that read
an unquoted value of code (core.RESERVED_WORD_RULES: two keyword rules, two literal rules and a key rule) skip a
value that is exactly a listed word as code writes it: unquoted, in ASCII lower case or capitals. The list holds only
words a person would not choose as a password (Gate A round 2). Everything else is as before the fix: a quoted value,
the other keyword rules, a word a person may choose, a longer value and another case. Each comparison here runs the
same text with the check switched off.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets import detect, vault  # noqa: E402
from maisecrets.detection import core, value_checks, wordlists  # noqa: E402

LISTED = wordlists.words("passwords/reserved-words")

# the lower-case keywords of each language the list names, from its reference (contextual keywords included)
TABLES = {
    "javascript": """await break case catch class const continue debugger default delete do else enum export extends
        false finally for function if implements import in instanceof interface let new null package private
        protected public return static super switch this throw true try typeof var void while with yield""",
    "typescript": """abstract accessor any as asserts async bigint boolean constructor declare get global infer is keyof
        module namespace never number object of out override readonly require satisfies set string symbol type
        undefined unique unknown""",
    "python": """and as assert async await break class continue def del elif else except finally for from global if
        import in is lambda nonlocal not or pass raise return try while with yield""",
    "java": """abstract assert boolean break byte case catch char class const continue default do double else enum
        extends final finally float for goto if implements import instanceof int interface long native new
        package permits private protected public record return sealed short static strictfp super switch
        synchronized this throw throws transient try var void volatile while yield""",
    "csharp": """abstract as base bool break byte case catch char checked class const continue decimal default
        delegate do double else enum event explicit extern false finally fixed float for foreach goto if implicit
        in int interface internal is lock long namespace nameof new null object operator out override params
        private protected public readonly ref return sbyte sealed short sizeof stackalloc static string struct
        switch this throw true try typeof uint ulong unchecked unsafe ushort using virtual void volatile while""",
    "go": """break case chan const continue default defer else fallthrough for func go goto if import interface map
        package range return select struct switch type var nil iota""",
    "c": """alignas alignof auto bool break case char const constexpr continue default do double else enum extern
        false float for goto if inline int long nullptr register restrict return short signed sizeof static
        static_assert struct switch thread_local true typedef typeof typeof_unqual union unsigned void volatile
        while""",
    # not the whole standard: the keywords of queries, tables and transactions
    "sql": """alter asc between cascade collate constraint create current_date current_timestamp current_user desc
        distinct except excluded exists fetch foreign having ilike insert intersect interval lateral nulls partition
        primary procedure recursive references returning rollback savepoint select session_user transaction
        truncate union unique unsigned update varchar""",
}
# a keyword that a person may choose as a password, or write after a label in prose: an everyday English word or a
# short one. It stays a value, `PASSWORD=unique` in a .env file is a string (Gate A of #29, round 2)
LEFT_OUT = frozenset("""
    alter and any as asc assert asserts auto await base between bool break byte cascade case catch chan char
    checked class collate constraint constructor continue create debugger decimal declare def default defer
    del delegate delete desc do double else event except exists explicit export extends false fetch final
    finally fixed float for foreign from get global go having if implicit import in infer inline insert int
    interface internal intersect iota is lambda lateral let lock long map module native never new nil not null
    nulls number object of operator or out override package params partition pass permits primary private
    protected public raise range record recursive ref references register require restrict return returning
    rollback satisfies sealed select set short signed static string super switch symbol synchronized this
    thread_local throw throws transaction transient true truncate try type unchecked undefined union unique
    unknown unsafe update using var virtual void volatile while with yield
""".split())

# the labels are split by `§`, as in tests/test_detect_rules.py
UNQUOTED = ("const sec§ret = {v};", "let pass§word = {v}", "api§_key={v}", "pass§word: {v}", "sec§ret: {v}")
QUOTED = ('api§_key = "{v}"', "sec§ret: '{v}'", 'sec§ret: "{v}"', 'api§_key => "{v}"', 'if pass§word == "{v}":',
          '"pass§word": "{v}";', "pass§word := `{v}`", 'token = "{v}";', "{{ secret: '{v}' }}")


def kinds(text: str) -> list:
    return sorted((m.kind, m.start, m.end) for m in detect.scan(text.replace("§", ""), channel="tool"))


def kinds_without_the_check(text: str) -> list:
    with mock.patch.object(value_checks, "is_reserved_word", lambda value: False):   # its own module
        return kinds(text)


class ListTests(unittest.TestCase):
    def test_each_keyword_of_a_table_is_listed_or_left_out_by_name(self):
        for lang, table in TABLES.items():
            with self.subTest(language=lang):
                self.assertEqual(sorted(set(table.split()) - LISTED - LEFT_OUT), [])

    def test_each_listed_word_is_a_keyword_of_a_table(self):
        known = set().union(*(t.split() for t in TABLES.values()))
        self.assertEqual(sorted(LISTED - known), [])
        self.assertEqual(sorted(LISTED & LEFT_OUT), [])


class SpellingTests(unittest.TestCase):
    def test_every_listed_word_in_a_code_spelling_is_reserved(self):
        for w in sorted(LISTED):
            for v in (w, w.upper(), w + ";", w.upper() + ";", " " + w + " "):
                with self.subTest(value=v):
                    self.assertTrue(core.is_reserved_word(v))
        for v in ("True", "False", "None", "Readonly"):
            self.assertFalse(core.is_reserved_word(v), "as origin/next: older filters decide on these")

    def test_another_case_a_longer_value_and_unicode_are_no_reserved_word(self):
        for w in sorted(LISTED):
            spellings = {w.capitalize(), w[:1].upper() + w[1:].upper().lower(), w + "7", "x" + w, w + "_", w + ",",
                         w[:-1], w.swapcase()[:1] + w[1:]}
            for v in spellings - {w, w.upper()}:
                if v in LISTED or v.upper() == v and v.lower() in LISTED:
                    continue   # asc without its last letter is the listed `as`
                with self.subTest(value=v):
                    self.assertFalse(core.is_reserved_word(v))
        # the Kelvin sign lowers to an ASCII k: the lower case of \u212aEYOF is keyof
        for v in ("true", "\uff34\uff32\uff35\uff25", "\u0130MPORT", "true\u00a0;", "TRUE\u0131", "none", "NONE",
                  "\u212aEYOF", "BREA\u212a"):
            with self.subTest(value=ascii(v)):
                self.assertFalse(core.is_reserved_word(v))

    def test_the_vault_quiets_the_same_spellings_the_detector_skips(self):
        # a stored `Readonly` is still a value for the detector, so the vault must not quiet it (Gate A of #29)
        made = set(vault.reserved_word_spellings())
        candidates = {s for w in LISTED | LEFT_OUT | {"true", "false", "none"}
                      for b in (w, w.capitalize(), w.upper()) for s in (b, b + ";")}
        self.assertEqual(made, {s for s in candidates if core.is_reserved_word(s)})


class ScanTests(unittest.TestCase):
    def test_an_unquoted_listed_word_gives_no_hit(self):
        for w in sorted(LISTED):
            for v in (w, w.upper(), w + ";"):
                for form in UNQUOTED:
                    text = form.format(v=v)
                    with self.subTest(text=text):
                        self.assertEqual(kinds(text), [])

    def test_the_check_changes_only_unquoted_values_of_the_listed_rules(self):
        # the other five ds-keyword rules, a quoted value, and every other rule find what they found before; a
        # literal rule must not take the word that a keyword rule now leaves (implements, procedure)
        changed = 0
        for w in sorted(LISTED):
            for form in QUOTED + UNQUOTED:
                text = form.format(v=w)
                now, before = kinds(text), kinds_without_the_check(text)
                if now == before:
                    continue
                with self.subTest(text=text):
                    self.assertIn(form, UNQUOTED)
                    self.assertEqual(sorted(set(now) - set(before)), [], "the check only takes hits away")
                    self.assertTrue({k[0] for k in set(before) - set(now)} <= core.RESERVED_WORD_RULES)
                changed += 1
        self.assertGreater(changed, len(LISTED), "premise: the check takes hits away")

    def test_a_quoted_listed_word_is_still_a_hit(self):
        # a quoted string is a string, not a keyword: the word in quotes is found by each rule that found it
        for text in ('api§_key = "readonly"', "sec§ret: 'distinct'", 'sec§ret: "unsigned"', 'api§_key => "readonly"',
                     'if pass§word == "interval":'):
            with self.subTest(text=text):
                self.assertTrue(kinds(text))
                self.assertEqual(kinds(text), kinds_without_the_check(text))

    def test_a_word_a_person_may_choose_is_found_as_before(self):
        # Gate A round 2: `PASSWORD=unique` gave no hit. Each left-out word finds what it found before #29, also in a
        # .env line and after a colon; these gave a hit before and must still give one
        for w in sorted(LEFT_OUT):
            for form in ("PASS§WORD={v}", "pass§word: {v}", "const sec§ret = {v};"):
                text = form.format(v=w)
                with self.subTest(text=text):
                    self.assertEqual(kinds(text), kinds_without_the_check(text))
        for w in ("unique", "select", "update", "create", "delete", "global"):
            with self.subTest(word=w):
                self.assertTrue(kinds("PASS§WORD=" + w), "a .env value is a string")

    def test_a_listed_word_as_a_url_parameter_is_still_a_hit(self):
        # a URL parameter is a value, not code: only the rules of RESERVED_WORD_RULES skip the word
        for w in ("procedure", "readonly", "volatile"):
            text = "https://api.example.com/v1?tok§en=" + w + "&page=2"
            with self.subTest(text=text):
                self.assertEqual([k[0] for k in kinds(text)], ["url-query-secret"])

    def test_another_case_or_a_longer_value_is_found_as_before(self):
        for w in sorted(LISTED):
            for v in (w.capitalize(), w + "7", "x" + w):
                if v == w:
                    continue
                text = "const sec§ret = {v};".format(v=v)
                with self.subTest(text=text):
                    self.assertEqual(kinds(text), kinds_without_the_check(text))


if __name__ == "__main__":
    unittest.main()
