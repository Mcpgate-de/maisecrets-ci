"""A context word counts as a whole word (core._has_context_word). Its substring precheck answers before the regex: a
word that is not in the window as a substring is not there as a whole word either. The answer is the regex's own on
the windows of every corpus text, for the context words of every rule."""
from __future__ import annotations

import os
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets.detection import core  # noqa: E402
from test_required_literals import _texts  # noqa: E402


def _regex_only(window: str, context: tuple) -> bool:
    rx = re.compile(r"(?<![a-z0-9äöüß])(?:" + "|".join(re.escape(c) for c in context) + r")(?![a-z0-9äöüß])")
    return rx.search(window) is not None


class ContextWordTests(unittest.TestCase):
    def test_the_precheck_answers_as_the_regex(self):
        contexts = sorted({r.context for r in core.rules() if getattr(r, "context", None)})
        self.assertGreater(len(contexts), 10, "premise: rules with context words")
        windows = []
        for t in _texts()[:400]:
            low = core._lower(t)
            windows += [low[i:i + 120] for i in range(0, min(len(low), 1200), 97)]
        windows += ["report", "ort", "kontonr.", "the password", "passwordless", ""]
        hits = 0
        for ctx in contexts:
            # each word alone, inside a word (a substring but no whole word), and before a digit
            own = [f"the {c}: x" for c in ctx[:5]] + [f"a{c}b" for c in ctx[:5]] + [f"{c}1" for c in ctx[:3]]
            for w in windows + own:
                got = core._has_context_word(w, ctx)
                self.assertEqual(got, _regex_only(w, ctx), (ctx[:3], w[:40]))
                hits += got
        self.assertGreater(hits, 50, "premise: some windows hold a context word")


if __name__ == "__main__":
    unittest.main()
