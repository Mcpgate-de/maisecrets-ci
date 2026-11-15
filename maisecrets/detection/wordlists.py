"""The word lists of the detection core as data files (#54): rules/words/<folder>/<name>.txt, one entry per
line, `#` starts a comment line; a comment line inside the list opens a block of entries that it explains.
rules/words/README.md names every file and its effect. A contributor adds a word as one line; the maintainer
measures the false alarms of the full benchmark splits before a merge (one word can change them a lot). Each
file is read once per process."""
from __future__ import annotations

import functools
from pathlib import Path

WORDS_DIR = Path(__file__).resolve().parent / "rules" / "words"


@functools.lru_cache(maxsize=None)
def words(name: str) -> frozenset:
    """The entries of rules/words/<name>.txt: each line stripped, blank lines and `#` lines left out."""
    text = (WORDS_DIR / f"{name}.txt").read_text(encoding="utf-8")
    return frozenset(x.strip() for x in text.splitlines() if x.strip() and not x.lstrip().startswith("#"))


@functools.lru_cache(maxsize=None)
def word_tuple(name: str) -> tuple:
    """The entries of rules/words/<name>.txt as a sorted tuple, for str.endswith and str.startswith."""
    return tuple(sorted(words(name)))
