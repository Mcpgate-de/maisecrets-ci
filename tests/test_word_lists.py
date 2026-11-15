"""The word lists of the detection core as files (#54, detection/wordlists.py): the first line says the effect,
each block of a file (between comment lines) is sorted, the file has no duplicate and no blank entry, a list that
its head calls lower case holds no capital letter, and README.md names every file. A contributor who adds a word
keeps these rules; the test names the file."""
from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets.detection import wordlists  # noqa: E402


class WordListFileTests(unittest.TestCase):
    def test_every_file_is_sorted_unique_and_in_its_case(self):
        files = sorted(wordlists.WORDS_DIR.rglob("*.txt"))
        self.assertGreaterEqual(len(files), 98)
        for f in files:
            with self.subTest(file=str(f.relative_to(wordlists.WORDS_DIR))):
                lines = f.read_text(encoding="utf-8").splitlines()
                head = [x for x in lines if x.startswith("#")]
                entries = [x for x in lines if x and not x.startswith("#")]
                self.assertTrue(head, "a head comment says what the list is")
                self.assertRegex(lines[0], r"^# Effect: a word here makes maisecrets (mask LESS|find MORE)\.",
                                 "the first line says what a new word does")
                self.assertTrue(lines[1].startswith("# Format:"))
                self.assertTrue(entries)
                self.assertEqual(entries, [x.strip() for x in entries], "no blanks around an entry")
                self.assertEqual(len(entries), len(set(entries)), "each entry once")
                block: list = []
                for x in lines + ["#"]:     # a comment line inside the list closes the block before it
                    if x.startswith("#"):
                        self.assertEqual(block, sorted(block), "each block sorted")
                        block = []
                    elif x:
                        block.append(x)
                if "lower case" in " ".join(head):
                    self.assertEqual([x for x in entries if x != x.lower()], [])

    def test_the_readme_names_every_file_and_no_other(self):
        readme = (wordlists.WORDS_DIR / "README.md").read_text(encoding="utf-8")
        named = set(re.findall(r"`([a-z-]+/[a-z-]+\.txt)`", readme))
        files = {f.relative_to(wordlists.WORDS_DIR).as_posix() for f in wordlists.WORDS_DIR.rglob("*.txt")}
        self.assertEqual(named, files)

    def test_the_loader_reads_the_entries_and_skips_comments(self):
        got = wordlists.words("name-service/test-runner-words")
        self.assertIn("skipped", got)
        self.assertFalse(any(x.startswith("#") for x in got))
        self.assertIs(got, wordlists.words("name-service/test-runner-words"), "read once per process")

    def test_a_tuple_list_is_sorted_and_holds_the_same_entries(self):
        got = wordlists.word_tuple("phones/phone-cues")
        self.assertEqual(got, tuple(sorted(wordlists.words("phones/phone-cues"))))
        self.assertIsInstance(got, tuple)


if __name__ == "__main__":
    unittest.main()
